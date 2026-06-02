package windows

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/containernetworking/plugins/pkg/hns"
	"github.com/juju/errors"
	"github.com/sirupsen/logrus"
)

// endpointResources is a minimal struct for extracting the vNIC attachment
// state from an HCN endpoint's Health.Extra.Resources field.  The State
// field mirrors the HNS v1 endpoint state:
//
//	1 = Created  — vNIC not yet attached to the vSwitch
//	3 = Attached — vNIC is live; VFP rules can be programmed
//
// The Resources JSON is only populated when the HCN query uses
// HostComputeQueryFlagsDetailed; it is absent with the default
// HostComputeQueryFlagsNone.
type endpointResources struct {
	State uint16 `json:"State"`
}

// waitForEndpointVNICAttach polls the HCN endpoint identified by endpointID
// until its vNIC transitions to State:3 (attached to the vSwitch) or until
// timeout is exceeded.
//
// The query MUST use HostComputeQueryFlagsDetailed; without that flag HCN
// omits the Health.Extra.Resources field entirely, so State is never populated
// and every call would time out (which was the vfp-optc regression: a silent
// 10-second delay that pushed AddNamespaceEndpoint past the SLB dynnat
// programming window).
//
// On timeout the function returns a non-nil error; on HCN query failure the
// error is returned immediately.
func waitForEndpointVNICAttach(endpointID string, timeout time.Duration, logger *logrus.Entry) error {
	deadline := time.Now().Add(timeout)

	// HostComputeQueryFlagsDetailed is required to populate Health.Extra.Resources.
	// The default query (HostComputeQueryFlagsNone) omits that field, making
	// State detection impossible.
	filterJSON, err := json.Marshal(map[string]string{"ID": endpointID})
	if err != nil {
		return fmt.Errorf("waitForEndpointVNICAttach: failed to build query filter: %w", err)
	}
	detailedQuery := hcn.HostComputeQuery{
		SchemaVersion: hcn.SchemaVersion{Major: 2, Minor: 0},
		Flags:         hcn.HostComputeQueryFlagsDetailed,
		Filter:        string(filterJSON),
	}

	for {
		endpoints, err := hcn.ListEndpointsQuery(detailedQuery)
		if err != nil {
			return fmt.Errorf("waitForEndpointVNICAttach: HCN query failed: %w", err)
		}
		if len(endpoints) == 0 {
			return fmt.Errorf("waitForEndpointVNICAttach: endpoint %s not found", endpointID)
		}
		ep := &endpoints[0]

		if len(ep.Health.Extra.Resources) > 0 {
			var res endpointResources
			if jsonErr := json.Unmarshal(ep.Health.Extra.Resources, &res); jsonErr == nil {
				if res.State >= 3 {
					logger.Debugf("Endpoint %s reached vNIC State:%d (attached)", endpointID, res.State)
					return nil
				}
				logger.Debugf("Endpoint %s vNIC State:%d, waiting for State:3 (vSwitch attach)", endpointID, res.State)
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("endpoint %s did not reach vNIC State:3 within %v", endpointID, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// vnICAttachTimeout is the maximum time we wait for an HCN endpoint's vNIC to
// transition from State:1 (created) to State:3 (attached to the vSwitch)
// before calling AddNamespaceEndpoint.
//
// 60 seconds is chosen to accommodate nodes under heavy load during large
// Windows container image pulls (2–3 GiB images can cause >10 s vSwitch
// plumbing delays due to CPU/IO contention).  The Kubernetes CNI call timeout
// is 5 minutes by default, so 60 s leaves ample headroom.
const vnICAttachTimeout = 60 * time.Second

// addHcnEndpointWhenReady is a drop-in replacement for hns.AddHcnEndpoint that
// inserts a wait for the endpoint's vNIC to reach State:3 (attached to the
// vSwitch) between Create() and AddNamespaceEndpoint.
//
// Background: hcn.AddNamespaceEndpoint programs SLB VFP rules for the
// endpoint.  If the vNIC has not yet been attached to the vSwitch (State:1),
// HNS silently skips OutBoundNAT rule programming.  Waiting for State:3
// before calling AddNamespaceEndpoint ensures the rules are applied correctly.
//
// If the vNIC does not reach State:3 within vnICAttachTimeout the CNI ADD
// call fails with an error.  This causes the pod to be retried rather than
// starting silently with broken SNAT rules.
func addHcnEndpointWhenReady(
	epName string,
	expectedNetworkID string,
	namespace string,
	makeEndpoint hns.HcnEndpointMakerFunc,
	logger *logrus.Entry,
) (*hcn.HostComputeEndpoint, error) {
	// Check for a pre-existing endpoint (mirrors hns.AddHcnEndpoint).
	hcnEndpoint, err := hcn.GetEndpointByName(epName)
	if err != nil {
		if !hcn.IsNotFoundError(err) {
			return nil, errors.Annotatef(err, "failed to find HostComputeEndpoint %s", epName)
		}
	}

	// Delete the endpoint if it belongs to the wrong network.
	if hcnEndpoint != nil {
		if !strings.EqualFold(hcnEndpoint.HostComputeNetwork, expectedNetworkID) {
			if err := hcnEndpoint.Delete(); err != nil {
				return nil, errors.Annotatef(err, "failed to delete corrupted HostComputeEndpoint %s", epName)
			}
			hcnEndpoint = nil
		}
	}

	// Create the endpoint if it does not exist yet.
	isNewEndpoint := false
	if hcnEndpoint == nil {
		if hcnEndpoint, err = makeEndpoint(); err != nil {
			return nil, errors.Annotate(err, "failed to make a new HostComputeEndpoint")
		}
		if hcnEndpoint, err = hcnEndpoint.Create(); err != nil {
			return nil, errors.Annotate(err, "failed to create the new HostComputeEndpoint")
		}
		isNewEndpoint = true
	}

	// Wait for the vNIC to be attached to the vSwitch (State:3) before adding
	// the endpoint to the namespace.  AddNamespaceEndpoint programs SLB VFP
	// rules; calling it while the port is in State:1 causes HNS to silently
	// skip OutBoundNAT rule programming.
	//
	// On timeout we fail the CNI ADD rather than falling through with State:1.
	// A pod that fails to start is retried by the kubelet; a pod that starts
	// with missing SNAT rules is silently broken and never self-heals.
	if waitErr := waitForEndpointVNICAttach(hcnEndpoint.Id, vnICAttachTimeout, logger); waitErr != nil {
		if isNewEndpoint {
			if removeErr := hns.RemoveHcnEndpoint(epName); removeErr != nil {
				logger.WithError(removeErr).Warningf(
					"failed to remove HostComputeEndpoint %s after vNIC attach timeout", epName)
			}
		}
		return nil, fmt.Errorf("addHcnEndpointWhenReady: %w", waitErr)
	}

	// Add the endpoint to the network namespace, this programs VFP rules.
	if err = hcn.AddNamespaceEndpoint(namespace, hcnEndpoint.Id); err != nil {
		if isNewEndpoint {
			if removeErr := hns.RemoveHcnEndpoint(epName); removeErr != nil {
				return nil, errors.Annotatef(removeErr,
					"failed to remove HostComputeEndpoint %s after AddNamespaceEndpoint failure", epName)
			}
		}
		return nil, errors.Annotatef(err,
			"failed to add HostComputeEndpoint %s to HostComputeNamespace %s", epName, namespace)
	}
	return hcnEndpoint, nil
}

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
// The Resources JSON is only returned when querying with
// HostComputeQueryFlagsDetailed; it is accessible via
// HostComputeEndpoint.Health.Extra.Resources.
type endpointResources struct {
	State uint16 `json:"State"`
}

// waitForEndpointVNICAttach polls the HCN endpoint identified by endpointID
// until its vNIC transitions to State:3 (attached to the vSwitch) or until
// timeout is exceeded.
//
// On timeout the function returns a non-nil error; on HCN query failure the
// error is returned immediately.
func waitForEndpointVNICAttach(endpointID string, timeout time.Duration, logger *logrus.Entry) error {
	// Build the query once outside the loop; it never changes.
	// HostComputeQueryFlagsDetailed is required so that Health.Extra.Resources
	// (which contains the vNIC attachment State) is included in the response.
	// The default query (HostComputeQueryFlagsNone) omits this field entirely,
	// which would cause the state check below to never succeed and the wait to
	// always time out.
	filterBytes, err := json.Marshal(map[string]string{"ID": endpointID})
	if err != nil {
		return fmt.Errorf("waitForEndpointVNICAttach: failed to marshal filter: %w", err)
	}
	query := hcn.HostComputeQuery{
		SchemaVersion: hcn.V2SchemaVersion(),
		Flags:         hcn.HostComputeQueryFlagsDetailed,
		Filter:        string(filterBytes),
	}

	deadline := time.Now().Add(timeout)
	for {
		eps, err := hcn.ListEndpointsQuery(query)
		if err != nil {
			return fmt.Errorf("waitForEndpointVNICAttach: HCN query failed: %w", err)
		}
		if len(eps) == 0 {
			return fmt.Errorf("waitForEndpointVNICAttach: endpoint %s not found", endpointID)
		}

		if len(eps[0].Health.Extra.Resources) > 0 {
			var res endpointResources
			if jsonErr := json.Unmarshal(eps[0].Health.Extra.Resources, &res); jsonErr == nil {
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

// addHcnEndpointWhenReady is a drop-in replacement for hns.AddHcnEndpoint that
// inserts a wait for the endpoint's vNIC to reach State:3 (attached to the
// vSwitch) between Create() and AddNamespaceEndpoint.
//
// Background: hcn.AddNamespaceEndpoint programs SLB VFP rules for the
// endpoint.  If the vNIC has not yet been attached to the vSwitch (State:1),
// HNS silently skips OutBoundNAT rule programming.  Waiting for State:3
// before calling AddNamespaceEndpoint ensures the rules are applied correctly.
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
	if waitErr := waitForEndpointVNICAttach(hcnEndpoint.Id, 10*time.Second, logger); waitErr != nil {
		logger.WithError(waitErr).Warning(
			"Timed out waiting for endpoint vNIC State:3 before AddNamespaceEndpoint; OutBoundNAT rules may be missing")
	}

	// Add the endpoint to the network namespace; this programs VFP rules.
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

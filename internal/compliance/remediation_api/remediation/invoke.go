package remediation

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	analysisclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	analysisoperations "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	remediationmodels "github.com/panther-labs/panther/api/gateway/remediation/models"
	resourcesclient "github.com/panther-labs/panther/api/gateway/resources/client"
	resourcesoperations "github.com/panther-labs/panther/api/gateway/resources/client/operations"
	resourcesmodels "github.com/panther-labs/panther/api/gateway/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const remediationAction = "remediate"
const listRemediationsAction = "listRemediations"

var (
	remediationLambdaArn     = os.Getenv("REMEDIATION_LAMBDA_ARN")
	policiesServiceHostname  = os.Getenv("POLICIES_SERVICE_HOSTNAME")
	policiesServicePath      = os.Getenv("POLICIES_SERVICE_PATH")
	resourcesServiceHostname = os.Getenv("RESOURCES_SERVICE_HOSTNAME")
	resourcesServicePath     = os.Getenv("RESOURCES_SERVICE_PATH")

	awsSession     = session.Must(session.NewSession())
	httpClient     = gatewayapi.GatewayClient(awsSession)
	policiesConfig = analysisclient.DefaultTransportConfig().
			WithBasePath(policiesServicePath).
			WithHost(policiesServiceHostname)
	policiesClient = analysisclient.NewHTTPClientWithConfig(nil, policiesConfig)

	resourcesConfig = resourcesclient.DefaultTransportConfig().
			WithBasePath(resourcesServicePath).
			WithHost(resourcesServiceHostname)
	resourcesClient = resourcesclient.NewHTTPClientWithConfig(nil, resourcesConfig)

	ErrNotFound = errors.New("Remediation not associated with policy")
)

// Remediate will invoke remediation action in an AWS account
func (remediator *Invoker) Remediate(remediation *remediationmodels.RemediateResource) error {
	zap.L().Debug("handling remediation",
		zap.Any("policyId", remediation.PolicyID),
		zap.Any("resourceId", remediation.ResourceID))

	policy, err := getPolicy(string(remediation.PolicyID))
	if err != nil {
		return errors.Wrap(err, "Encountered issue when getting policy")
	}

	if policy.AutoRemediationID == "" {
		return ErrNotFound
	}

	resource, err := getResource(string(remediation.ResourceID))
	if err != nil {
		return errors.Wrap(err, "Encountered issue when getting resource")
	}
	remediationPayload := &Payload{
		RemediationID: string(policy.AutoRemediationID),
		Resource:      resource.Attributes,
		Parameters:    policy.AutoRemediationParameters,
	}
	lambdaInput := &LambdaInput{
		Action:  aws.String(remediationAction),
		Payload: remediationPayload,
	}

	_, err = remediator.invokeLambda(lambdaInput)
	if err != nil {
		return errors.Wrap(err, "failed to invoke remediator")
	}

	zap.L().Debug("finished remediate action")
	return nil
}

//GetRemediations invokes the Lambda in customer account and retrieves the list of available remediations
func (remediator *Invoker) GetRemediations() (*remediationmodels.Remediations, error) {
	zap.L().Info("getting list of remediations")

	lambdaInput := &LambdaInput{Action: aws.String(listRemediationsAction)}

	result, err := remediator.invokeLambda(lambdaInput)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("got response from Remediation Lambda",
		zap.String("lambdaResponse", string(result)))

	var remediations remediationmodels.Remediations
	if err := jsoniter.Unmarshal(result, &remediations); err != nil {
		return nil, err
	}

	zap.L().Debug("finished action to get remediations")
	return &remediations, nil
}

func getPolicy(policyID string) (*analysismodels.Policy, error) {
	policy, err := policiesClient.Operations.GetPolicy(&analysisoperations.GetPolicyParams{
		PolicyID:   policyID,
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, err
	}
	return policy.Payload, nil
}

func getResource(resourceID string) (*resourcesmodels.Resource, error) {
	resource, err := resourcesClient.Operations.GetResource(&resourcesoperations.GetResourceParams{
		ResourceID: resourceID,
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, err
	}
	return resource.Payload, nil
}

func (remediator *Invoker) invokeLambda(lambdaInput *LambdaInput) ([]byte, error) {
	serializedPayload, err := jsoniter.Marshal(lambdaInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal lambda input")
	}

	invokeInput := &lambda.InvokeInput{
		Payload:      serializedPayload,
		FunctionName: aws.String(remediationLambdaArn),
	}

	response, err := remediator.lambdaClient.Invoke(invokeInput)
	if err != nil {
		return nil, err
	}

	if response.FunctionError != nil {
		return nil, errors.New("error invoking lambda: " + string(response.Payload))
	}

	zap.L().Debug("finished Lambda invocation")
	return response.Payload, nil
}

//LambdaInput is the input to the Remediation Lambda running in customer account
type LambdaInput struct {
	Action  *string     `json:"action"`
	Payload interface{} `json:"payload,omitempty"`
}

// Payload is the input to the Lambda running in customer account
// that will perform the remediation tasks
type Payload struct {
	RemediationID string      `json:"remediationId"`
	Resource      interface{} `json:"resource"`
	Parameters    interface{} `json:"parameters"`
}

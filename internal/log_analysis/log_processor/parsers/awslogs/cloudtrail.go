package awslogs

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
	"errors"
	jsoniter "github.com/json-iterator/go"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/extract"
)

type CloudTrailRecords struct {
	Records []*CloudTrail `json:"Records" validate:"required,dive"`
}

// CloudTrail is a record from the Records[*] JSON of an AWS CloudTrail API log.
// nolint:lll
type CloudTrail struct {
	AdditionalEventData *jsoniter.RawMessage    `json:"additionalEventData,omitempty" description:"Additional data about the event that was not part of the request or response."`
	APIVersion          *string                 `json:"apiVersion,omitempty" description:"Identifies the API version associated with the AwsApiCall eventType value."`
	AWSRegion           *string                 `json:"awsRegion,omitempty" validate:"required" description:"The AWS region that the request was made to, such as us-east-2."`
	ErrorCode           *string                 `json:"errorCode,omitempty" description:"The AWS service error if the request returns an error."`
	ErrorMessage        *string                 `json:"errorMessage,omitempty" description:"If the request returns an error, the description of the error. This message includes messages for authorization failures. CloudTrail captures the message logged by the service in its exception handling."`
	EventID             *string                 `json:"eventID,omitempty" validate:"required" description:"GUID generated by CloudTrail to uniquely identify each event. You can use this value to identify a single event. For example, you can use the ID as a primary key to retrieve log data from a searchable database."`
	EventName           *string                 `json:"eventName,omitempty" validate:"required" description:"The requested action, which is one of the actions in the API for that service."`
	EventSource         *string                 `json:"eventSource,omitempty" validate:"required" description:"The service that the request was made to. This name is typically a short form of the service name without spaces plus .amazonaws.com."`
	EventTime           *timestamp.RFC3339      `json:"eventTime,omitempty" validate:"required" description:"The date and time the request was made, in coordinated universal time (UTC)."`
	EventType           *string                 `json:"eventType,omitempty" validate:"required" description:"Identifies the type of event that generated the event record. This can be the one of the following values: AwsApiCall, AwsServiceEvent, AwsConsoleSignIn"`
	EventVersion        *string                 `json:"eventVersion,omitempty" validate:"required" description:"The version of the log event format."`
	ManagementEvent     *bool                   `json:"managementEvent,omitempty" description:"A Boolean value that identifies whether the event is a management event. managementEvent is shown in an event record if eventVersion is 1.06 or higher, and the event type is one of the following: AwsApiCall, AwsConsoleAction, AwsConsoleSignIn,  AwsServiceEvent"`
	ReadOnly            *bool                   `json:"readOnly,omitempty" description:"Identifies whether this operation is a read-only operation."`
	RecipientAccountID  *string                 `json:"recipientAccountId,omitempty" validate:"omitempty,len=12,numeric" description:"Represents the account ID that received this event. The recipientAccountID may be different from the CloudTrail userIdentity Element accountId. This can occur in cross-account resource access."`
	RequestID           *string                 `json:"requestID,omitempty" description:"The value that identifies the request. The service being called generates this value."`
	RequestParameters   *jsoniter.RawMessage    `json:"requestParameters,omitempty" description:"The parameters, if any, that were sent with the request. These parameters are documented in the API reference documentation for the appropriate AWS service."`
	Resources           []CloudTrailResources   `json:"resources,omitempty" description:"A list of resources accessed in the event."`
	ResponseElements    *jsoniter.RawMessage    `json:"responseElements,omitempty" description:"The response element for actions that make changes (create, update, or delete actions). If an action does not change state (for example, a request to get or list objects), this element is omitted. These actions are documented in the API reference documentation for the appropriate AWS service."`
	ServiceEventDetails *jsoniter.RawMessage    `json:"serviceEventDetails,omitempty" description:"Identifies the service event, including what triggered the event and the result."`
	SharedEventID       *string                 `json:"sharedEventID,omitempty" description:"GUID generated by CloudTrail to uniquely identify CloudTrail events from the same AWS action that is sent to different AWS accounts."`
	SourceIPAddress     *string                 `json:"sourceIPAddress,omitempty" validate:"required" description:"The IP address that the request was made from. For actions that originate from the service console, the address reported is for the underlying customer resource, not the console web server. For services in AWS, only the DNS name is displayed."`
	UserAgent           *string                 `json:"userAgent,omitempty" description:"The agent through which the request was made, such as the AWS Management Console, an AWS service, the AWS SDKs or the AWS CLI."`
	UserIdentity        *CloudTrailUserIdentity `json:"userIdentity,omitempty" validate:"required" description:"Information about the user that made a request."`
	VPCEndpointID       *string                 `json:"vpcEndpointId,omitempty" description:"Identifies the VPC endpoint in which requests were made from a VPC to another AWS service, such as Amazon S3."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// CloudTrailResources are the AWS resources used in the API call.
type CloudTrailResources struct {
	ARN       *string `json:"arn"`
	AccountID *string `json:"accountId"`
	Type      *string `json:"type"`
}

// CloudTrailUserIdentity contains details about the type of IAM identity that made the request.
type CloudTrailUserIdentity struct {
	Type             *string                   `json:"type,omitempty"`
	PrincipalID      *string                   `json:"principalId,omitempty"`
	ARN              *string                   `json:"arn,omitempty"`
	AccountID        *string                   `json:"accountId,omitempty"`
	AccessKeyID      *string                   `json:"accessKeyId,omitempty"`
	Username         *string                   `json:"userName,omitempty"`
	SessionContext   *CloudTrailSessionContext `json:"sessionContext,omitempty"`
	InvokedBy        *string                   `json:"invokedBy,omitempty"`
	IdentityProvider *string                   `json:"identityProvider,omitempty"`
}

// CloudTrailSessionContext provides information about a session created for temporary credentials.
type CloudTrailSessionContext struct {
	Attributes          *CloudTrailSessionContextAttributes          `json:"attributes,omitempty"`
	SessionIssuer       *CloudTrailSessionContextSessionIssuer       `json:"sessionIssuer,omitempty"`
	WebIDFederationData *CloudTrailSessionContextWebIDFederationData `json:"webIdFederationData,omitempty"`
}

// CloudTrailSessionContextAttributes  contains the attributes of the Session context object
type CloudTrailSessionContextAttributes struct {
	MfaAuthenticated *string `json:"mfaAuthenticated,omitempty"`
	CreationDate     *string `json:"creationDate,omitempty"`
}

// CloudTrailSessionContextSessionIssuer contains information for the SessionContextSessionIssuer
type CloudTrailSessionContextSessionIssuer struct {
	Type        *string `json:"type,omitempty"`
	PrincipalID *string `json:"principalId,omitempty"`
	Arn         *string `json:"arn,omitempty"`
	AccountID   *string `json:"accountId,omitempty"`
	Username    *string `json:"userName,omitempty"`
}

// CloudTrailSessionContextWebIDFederationData contains Web ID federation data
type CloudTrailSessionContextWebIDFederationData struct {
	FederatedProvider *string              `json:"federatedProvider,omitempty"`
	Attributes        *jsoniter.RawMessage `json:"attributes,omitempty"`
}

// CloudTrailParser parses CloudTrail logs
type CloudTrailParser struct{}

var _ parsers.LogParser = (*CloudTrailParser)(nil)

func (p *CloudTrailParser) New() parsers.LogParser {
	return &CloudTrailParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *CloudTrailParser) Parse(log string) ([]*parsers.PantherLog, error) {
	cloudTrailRecords := &CloudTrailRecords{}
	err := jsoniter.UnmarshalFromString(log, cloudTrailRecords)
	if err != nil {
		return nil, err
	}

	for _, event := range cloudTrailRecords.Records {
		event.updatePantherFields()
	}

	if err := parsers.Validator.Struct(cloudTrailRecords); err != nil {
		return nil, err
	}
	result := make([]*parsers.PantherLog, len(cloudTrailRecords.Records))
	for i, event := range cloudTrailRecords.Records {
		result[i] = event.Log()
	}
	return result, nil
}

// LogType returns the log type supported by this parser
func (p *CloudTrailParser) LogType() string {
	return TypeCloudTrail
}

func (event *CloudTrail) updatePantherFields() {
	event.SetCoreFields(TypeCloudTrail, event.EventTime, event)

	// structured (parsed) fields
	event.AppendAnyIPAddressPtr(event.SourceIPAddress)
	event.AppendAnyAWSAccountIdPtrs(event.RecipientAccountID)

	for _, resource := range event.Resources {
		event.AppendAnyAWSARNPtrs(resource.ARN)
		event.AppendAnyAWSAccountIdPtrs(resource.AccountID)
	}
	if event.UserIdentity != nil {
		event.AppendAnyAWSAccountIdPtrs(event.UserIdentity.AccountID)
		event.AppendAnyAWSARNPtrs(event.UserIdentity.ARN)

		if event.UserIdentity.SessionContext != nil {
			if event.UserIdentity.SessionContext.SessionIssuer != nil {
				event.AppendAnyAWSAccountIdPtrs(event.UserIdentity.SessionContext.SessionIssuer.AccountID)
				event.AppendAnyAWSARNPtrs(event.UserIdentity.SessionContext.SessionIssuer.Arn)
			}
		}
	}

	// polymorphic (unparsed) fields
	awsExtractor := NewAWSExtractor(&(event.AWSPantherLog))
	extract.Extract(event.AdditionalEventData, awsExtractor)
	extract.Extract(event.RequestParameters, awsExtractor)
	extract.Extract(event.ResponseElements, awsExtractor)
	extract.Extract(event.ServiceEventDetails, awsExtractor)
	if event.UserIdentity != nil &&
		event.UserIdentity.SessionContext != nil &&
		event.UserIdentity.SessionContext.WebIDFederationData != nil {

		extract.Extract(event.UserIdentity.SessionContext.WebIDFederationData.Attributes, awsExtractor)
	}
}

// CloudTrailStreamingParser parses cloudtrail records without using too much memory.
type CloudTrailStreamingParser struct{}

var _ parsers.Interface = (*CloudTrailStreamingParser)(nil)

func (*CloudTrailStreamingParser) ParseLog(log string) ([]*parsers.Result, error) {
	iter := parsers.JSON.BorrowIterator([]byte(`null`))
	r := strings.NewReader(log)
	iter.Reset(r)
	// Seek to `Records key`
	for key := iter.ReadObject(); key != ""; key = iter.ReadObject() {
		if key != `Records` {
			iter.Skip()
			continue
		}
		return nil, parsers.NewStreamResultsError(&cloudTrailResultStream{
			iter: iter,
		})
	}
	return nil, errors.New(`no records`)
}

type cloudTrailResultStream struct {
	err  error
	iter *jsoniter.Iterator
}

var _ parsers.ResultStream = (*cloudTrailResultStream)(nil)

func (s *cloudTrailResultStream) Next() (*parsers.Result, error) {
	if s.err != nil {
		return nil, s.err
	}
	iter := s.iter
	if iter == nil {
		return nil, nil
	}
	if !iter.ReadArray() {
		return nil, s.close(nil)
	}
	event := CloudTrail{}
	iter.ReadVal(&event)
	if err := iter.Error; err != nil {
		return nil, s.close(err)
	}
	event.updatePantherFields()
	if err := parsers.Validator.Struct(&event); err != nil {
		return nil, s.close(err)
	}
	result, err := event.Result()
	if err != nil {
		return nil, s.close(err)
	}
	return result, nil
}

func (s *cloudTrailResultStream) close(err error) error {
	iter := s.iter
	s.err, s.iter = err, nil
	iter.Pool().ReturnIterator(iter)
	return err
}

package mage

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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/config"
)

const (
	// Python layer
	layerSourceDir = "out/pip/analysis/python"
	layerZipfile   = "out/layer.zip"
)

// Not all AWS services are available in every region. In particular, Panther will currently NOT work in:
//     n. california, us-gov, china, paris, stockholm, brazil, osaka, or bahrain
// These regions are missing combinations of AppSync, Cognito, Athena, and/or Glue.
// https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services
var supportedRegions = map[string]bool{
	"ap-northeast-1": true, // tokyo
	"ap-northeast-2": true, // seoul
	"ap-south-1":     true, // mumbai
	"ap-southeast-1": true, // singapore
	"ap-southeast-2": true, // sydney
	"ca-central-1":   true, // canada
	"eu-central-1":   true, // frankfurt
	"eu-west-1":      true, // ireland
	"eu-west-2":      true, // london
	"us-east-1":      true, // n. virginia
	"us-east-2":      true, // ohio
	"us-west-2":      true, // oregon
}

// NOTE: Mage ignores the first word of the comment if it matches the function name.
// So the comment below is intentionally "Deploy Deploy"

// Deploy Deploy Panther to your AWS account
func Deploy() {
	start := time.Now()

	getSession()
	deployPreCheck(*awsSession.Config.Region, true)

	if stack := os.Getenv("STACK"); stack != "" {
		stack = strings.ToLower(strings.TrimSpace(stack))
		if !strings.HasPrefix(stack, "panther-") {
			stack = "panther-" + stack
		}
		if err := deploySingleStack(stack); err != nil {
			logger.Fatal(err)
		}
		return
	}

	settings := getSettings()
	accountID := getAccountID()
	logger.Infof("deploying Panther %s to account %s (%s)", gitVersion, accountID, *awsSession.Config.Region)

	setFirstUser(settings)
	outputs := bootstrap(settings)
	deployMainStacks(settings, accountID, outputs)

	logger.Infof("deploy: finished successfully in %s", time.Since(start).Round(time.Second))
	logger.Infof("***** Panther URL = https://%s", outputs["LoadBalancerUrl"])
}

// Fail the deploy early if there is a known issue with the user's environment.
func deployPreCheck(awsRegion string, checkForOldVersion bool) {
	// Ensure the AWS region is supported
	if !supportedRegions[awsRegion] {
		logger.Fatalf("panther is not supported in %s region", awsRegion)
	}

	// Check the Go version (1.12 fails with a build error)
	if version := runtime.Version(); version <= "go1.12" {
		logger.Fatalf("go %s not supported, upgrade to 1.13+", version)
	}

	// Check the major node version
	nodeVersion, err := sh.Output("node", "--version")
	if err != nil {
		logger.Fatalf("failed to check node version: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(nodeVersion), "v12") {
		logger.Fatalf("node version must be v12.x.x, found %s", nodeVersion)
	}

	// Make sure docker is running
	if _, err = sh.Output("docker", "info"); err != nil {
		logger.Fatalf("docker is not available: %v", err)
	}

	// Ensure swagger is available
	if _, err = sh.Output(filepath.Join(setupDirectory, "swagger"), "version"); err != nil {
		logger.Fatalf("swagger is not available (%v): try 'mage setup'", err)
	}

	// Set global gitVersion, warn if not deploying a tagged release
	getGitVersion()

	// There were mage migrations to help with v1.3 and v1.4 source deployments,
	// but these were removed in v1.6. As a result, old deployments first need to upgrade to v1.5.1
	if checkForOldVersion {
		bootstrapVersion, err := awscfn.StackTag(cloudformation.New(awsSession), "PantherVersion", cfnstacks.Bootstrap)
		if err != nil {
			logger.Warnf("failed to describe stack %s: %v", cfnstacks.Bootstrap, err)
		}
		if bootstrapVersion != "" && bootstrapVersion < "v1.4.0" {
			logger.Fatalf("trying to upgrade from %s to %s will not work - upgrade to v1.5.1 first",
				bootstrapVersion, gitVersion)
		}
	}
}

func getAccountID() string {
	identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Fatalf("failed to get caller identity: %v", err)
	}
	return *identity.Account
}

func getSettings() *config.PantherConfig {
	settings, err := config.Settings()
	if err != nil {
		logger.Fatalf("failed to read config file %s: %v", config.Filepath, err)
	}
	return settings
}

// Prompt for the name and email of the initial user if not already defined.
func setFirstUser(settings *config.PantherConfig) {
	if settings.Setup.FirstUser.Email != "" {
		// Always use the values in the settings file first, if available
		return
	}

	input := models.LambdaInput{ListUsers: &models.ListUsersInput{}}
	var output models.ListUsersOutput
	err := genericapi.Invoke(lambda.New(awsSession), "panther-users-api", &input, &output)
	if err != nil && !strings.Contains(err.Error(), lambda.ErrCodeResourceNotFoundException) {
		logger.Fatalf("failed to list existing users: %v", err)
	}

	if len(output.Users) > 0 {
		// A user already exists - leave the setting blank.
		// This will "delete" the FirstUser custom resource in the web stack, but since that resource
		// has DeletionPolicy:Retain, CloudFormation will ignore it.
		return
	}

	// If there is no setting and no existing user, we have to prompt.
	fmt.Println("Who will be the initial Panther admin user?")
	firstName := prompt.Read("First name: ", prompt.NonemptyValidator)
	lastName := prompt.Read("Last name: ", prompt.NonemptyValidator)
	email := prompt.Read("Email: ", prompt.EmailValidator)
	settings.Setup.FirstUser = config.FirstUser{
		GivenName:  firstName,
		FamilyName: lastName,
		Email:      email,
	}
}

// Deploy a single stack for rapid developer iteration.
//
// Can only be used to update an existing deployment.
func deploySingleStack(stack string) error {
	client := cloudformation.New(awsSession)
	switch stack {
	case cfnstacks.Bootstrap:
		_, err := deployBootstrapStack(getSettings())
		return err
	case cfnstacks.Gateway:
		build.Lambda() // custom-resources
		_, err := deployBootstrapGatewayStack(getSettings(), awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap))
		return err
	case cfnstacks.Appsync:
		return deployAppsyncStack(awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap, cfnstacks.Gateway))
	case cfnstacks.Cloudsec:
		build.API()
		build.Lambda()
		return deployCloudSecurityStack(getSettings(), awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap, cfnstacks.Gateway))
	case cfnstacks.Core:
		build.API()
		build.Lambda()
		return deployCoreStack(getSettings(), awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap, cfnstacks.Gateway))
	case cfnstacks.Dashboard:
		bucket := awscfn.StackOutputs(client, logger, cfnstacks.Bootstrap)["SourceBucket"]
		return deployDashboardStack(bucket)
	case cfnstacks.Frontend:
		setFirstUser(getSettings())
		return deployFrontend(getAccountID(), awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap, cfnstacks.Gateway), getSettings())
	case cfnstacks.LogAnalysis:
		build.API()
		build.Lambda()
		return deployLogAnalysisStack(getSettings(), awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap, cfnstacks.Gateway))
	case cfnstacks.Onboard:
		return deployOnboardStack(getSettings(), awscfn.StackOutputs(client, logger,
			cfnstacks.Bootstrap))
	default:
		return fmt.Errorf("unknown stack '%s'", stack)
	}
}

// Deploy bootstrap stacks and build deployment artifacts.
//
// Returns combined outputs from bootstrap stacks.
func bootstrap(settings *config.PantherConfig) map[string]string {
	build.API()
	build.Lambda() // Lambda compilation required for most stacks, including bootstrap-gateway

	outputs, err := deployBootstrapStack(settings)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Infof("    √ %s finished (1/%d)", cfnstacks.Bootstrap, cfnstacks.NumStacks)

	// Deploy second bootstrap stack and merge outputs
	gatewayOutputs, err := deployBootstrapGatewayStack(settings, outputs)
	if err != nil {
		logger.Fatal(err)
	}

	for k, v := range gatewayOutputs {
		if _, exists := outputs[k]; exists {
			logger.Fatalf("output %s exists in both bootstrap stacks", k)
		}
		outputs[k] = v
	}

	logger.Infof("    √ %s finished (2/%d)", cfnstacks.Gateway, cfnstacks.NumStacks)
	return outputs
}

// Deploy main stacks (everything after bootstrap and bootstrap-gateway)
func deployMainStacks(settings *config.PantherConfig, accountID string, outputs map[string]string) {
	results := make(chan goroutineResult)
	count := 0

	// Appsync
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: cfnstacks.Appsync, err: deployAppsyncStack(outputs)}
	}(results)

	// Cloud security
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: cfnstacks.Cloudsec, err: deployCloudSecurityStack(settings, outputs)}
	}(results)

	// Core
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: cfnstacks.Core, err: deployCoreStack(settings, outputs)}
	}(results)

	// Dashboards
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: cfnstacks.Dashboard, err: deployDashboardStack(outputs["SourceBucket"])}
	}(results)

	// Log analysis
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: cfnstacks.LogAnalysis, err: deployLogAnalysisStack(settings, outputs)}
	}(results)

	// Wait for stacks to finish.
	// There are two stacks before and two stacks after.
	logResults(results, "deploy", 3, count+2, cfnstacks.NumStacks)

	go func(c chan goroutineResult) {
		// Web stack requires core stack to exist first
		c <- goroutineResult{summary: cfnstacks.Frontend, err: deployFrontend(accountID, outputs, settings)}
	}(results)

	// Onboard Panther to scan itself
	go func(c chan goroutineResult) {
		c <- goroutineResult{summary: cfnstacks.Onboard, err: deployOnboardStack(settings, outputs)}
	}(results)

	// Log stack results, counting where the last parallel group left off to give the illusion of
	// one continuous deploy progress tracker.
	logResults(results, "deploy", count+3, cfnstacks.NumStacks, cfnstacks.NumStacks)
}

func deployBootstrapStack(settings *config.PantherConfig) (map[string]string, error) {
	return deployTemplate(cfnstacks.BootstrapTemplate, "", cfnstacks.Bootstrap, map[string]string{
		"AccessLogsBucket":              settings.Setup.S3AccessLogsBucket,
		"AlarmTopicArn":                 settings.Monitoring.AlarmSnsTopicArn,
		"CloudWatchLogRetentionDays":    strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomDomain":                  settings.Web.CustomDomain,
		"DataReplicationBucket":         settings.Setup.DataReplicationBucket,
		"Debug":                         strconv.FormatBool(settings.Monitoring.Debug),
		"DeployFromSource":              "true",
		"EnableS3AccessLogs":            strconv.FormatBool(settings.Setup.EnableS3AccessLogs),
		"LoadBalancerSecurityGroupCidr": settings.Infra.LoadBalancerSecurityGroupCidr,
		"LogSubscriptionPrincipals":     strings.Join(settings.Setup.LogSubscriptions.PrincipalARNs, ","),
		"TracingMode":                   settings.Monitoring.TracingMode,
	})
}

func deployBootstrapGatewayStack(
	settings *config.PantherConfig,
	outputs map[string]string, // from bootstrap stack
) (map[string]string, error) {

	if err := embedAPISpec(); err != nil {
		return nil, err
	}

	if err := buildLayer(settings.Infra.PipLayer); err != nil {
		return nil, err
	}

	return deployTemplate(cfnstacks.GatewayTemplate, outputs["SourceBucket"], cfnstacks.Gateway, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"AthenaResultsBucket":        outputs["AthenaResultsBucket"],
		"AuditLogsBucket":            outputs["AuditLogsBucket"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CompanyDisplayName":         settings.Setup.Company.DisplayName,
		"CustomResourceVersion":      customResourceVersion(),
		"ImageRegistryName":          outputs["ImageRegistryName"],
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"ProcessedDataBucket":        outputs["ProcessedDataBucket"],
		"PythonLayerVersionArn":      settings.Infra.PythonLayerVersionArn,
		"TracingMode":                settings.Monitoring.TracingMode,
		"UserPoolId":                 outputs["UserPoolId"],
	})
}

// Build standard Python analysis layer in out/layer.zip if that file doesn't already exist.
func buildLayer(libs []string) error {
	if _, err := os.Stat(layerZipfile); err == nil {
		logger.Debugf("%s already exists, not rebuilding layer", layerZipfile)
		return nil
	}

	logger.Info("downloading python libraries " + strings.Join(libs, ","))
	if err := os.RemoveAll(layerSourceDir); err != nil {
		return fmt.Errorf("failed to remove layer directory %s: %v", layerSourceDir, err)
	}
	if err := os.MkdirAll(layerSourceDir, 0700); err != nil {
		return fmt.Errorf("failed to create layer directory %s: %v", layerSourceDir, err)
	}
	args := append([]string{"install", "-t", layerSourceDir}, libs...)
	if err := sh.Run("pip3", args...); err != nil {
		return fmt.Errorf("failed to download pip libraries: %v", err)
	}

	// The package structure needs to be:
	//
	// layer.zip
	// │ python/policyuniverse/
	// └ python/policyuniverse-VERSION.dist-info/
	//
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
	if err := shutil.ZipDirectory(filepath.Dir(layerSourceDir), layerZipfile, false); err != nil {
		return fmt.Errorf("failed to zip %s into %s: %v", layerSourceDir, layerZipfile, err)
	}

	return nil
}

func deployAppsyncStack(outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.AppsyncTemplate, outputs["SourceBucket"], cfnstacks.Appsync, map[string]string{
		"AlarmTopicArn":         outputs["AlarmTopicArn"],
		"AnalysisApi":           "https://" + outputs["AnalysisApiEndpoint"],
		"ApiId":                 outputs["GraphQLApiId"],
		"ComplianceApi":         "https://" + outputs["ComplianceApiEndpoint"],
		"CustomResourceVersion": customResourceVersion(),
		"RemediationApi":        "https://" + outputs["RemediationApiEndpoint"],
		"ResourcesApi":          "https://" + outputs["ResourcesApiEndpoint"],
		"ServiceRole":           outputs["AppsyncServiceRoleArn"],
	})
	return err
}

func deployCloudSecurityStack(settings *config.PantherConfig, outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.CloudsecTemplate, outputs["SourceBucket"], cfnstacks.Cloudsec, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"AnalysisApiId":              outputs["AnalysisApiId"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"ComplianceApiId":            outputs["ComplianceApiId"],
		"CustomResourceVersion":      customResourceVersion(),
		"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"ProcessedDataBucket":        outputs["ProcessedDataBucket"],
		"ProcessedDataTopicArn":      outputs["ProcessedDataTopicArn"],
		"PythonLayerVersionArn":      outputs["PythonLayerVersionArn"],
		"RemediationApiId":           outputs["RemediationApiId"],
		"ResourcesApiId":             outputs["ResourcesApiId"],
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,
	})
	return err
}

func deployCoreStack(settings *config.PantherConfig, outputs map[string]string) error {
	_, err := deployTemplate(cfnstacks.CoreTemplate, outputs["SourceBucket"], cfnstacks.Core, map[string]string{
		"AlarmTopicArn":              outputs["AlarmTopicArn"],
		"AnalysisApiId":              outputs["AnalysisApiId"],
		"AnalysisVersionsBucket":     outputs["AnalysisVersionsBucket"],
		"AppDomainURL":               outputs["LoadBalancerUrl"],
		"AthenaResultsBucket":        outputs["AthenaResultsBucket"],
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CompanyDisplayName":         settings.Setup.Company.DisplayName,
		"CompanyEmail":               settings.Setup.Company.Email,
		"ComplianceApiId":            outputs["ComplianceApiId"],
		"CustomResourceVersion":      customResourceVersion(),
		"Debug":                      strconv.FormatBool(settings.Monitoring.Debug),
		"DynamoScalingRoleArn":       outputs["DynamoScalingRoleArn"],
		"InputDataBucket":            outputs["InputDataBucket"],
		"InputDataTopicArn":          outputs["InputDataTopicArn"],
		"LayerVersionArns":           settings.Infra.BaseLayerVersionArns,
		"OutputsKeyId":               outputs["OutputsEncryptionKeyId"],
		"ProcessedDataBucket":        outputs["ProcessedDataBucket"],
		"SqsKeyId":                   outputs["QueueEncryptionKeyId"],
		"TracingMode":                settings.Monitoring.TracingMode,
		"UserPoolId":                 outputs["UserPoolId"],
	})
	return err
}

func deployDashboardStack(bucket string) error {
	if err := generateDashboards(); err != nil {
		return err
	}

	_, err := deployTemplate(cfnstacks.DashboardTemplate, bucket, cfnstacks.Dashboard, nil)
	return err
}

func deployLogAnalysisStack(settings *config.PantherConfig, outputs map[string]string) error {
	// this computes a signature of the deployed glue tables used for change detection, for CF use the Panther version
	tablesSignature, err := gluetables.DeployedTablesSignature(glue.New(awsSession))
	if err != nil {
		return err
	}

	_, err = deployTemplate(cfnstacks.LogAnalysisTemplate, outputs["SourceBucket"], cfnstacks.LogAnalysis, map[string]string{
		"AlarmTopicArn":                outputs["AlarmTopicArn"],
		"AnalysisApiId":                outputs["AnalysisApiId"],
		"AthenaResultsBucket":          outputs["AthenaResultsBucket"],
		"CloudWatchLogRetentionDays":   strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomResourceVersion":        customResourceVersion(),
		"Debug":                        strconv.FormatBool(settings.Monitoring.Debug),
		"InputDataBucket":              outputs["InputDataBucket"],
		"InputDataTopicArn":            outputs["InputDataTopicArn"],
		"LayerVersionArns":             settings.Infra.BaseLayerVersionArns,
		"LogProcessorLambdaMemorySize": strconv.Itoa(settings.Infra.LogProcessorLambdaMemorySize),
		"ProcessedDataBucket":          outputs["ProcessedDataBucket"],
		"ProcessedDataTopicArn":        outputs["ProcessedDataTopicArn"],
		"PythonLayerVersionArn":        outputs["PythonLayerVersionArn"],
		"SqsKeyId":                     outputs["QueueEncryptionKeyId"],
		"TablesSignature":              tablesSignature,
		"TracingMode":                  settings.Monitoring.TracingMode,
	})
	return err
}

func deployOnboardStack(settings *config.PantherConfig, outputs map[string]string) error {
	var err error
	if settings.Setup.OnboardSelf {
		_, err = deployTemplate(cfnstacks.OnboardTemplate, outputs["SourceBucket"], cfnstacks.Onboard, map[string]string{
			"AlarmTopicArn":         outputs["AlarmTopicArn"],
			"AuditLogsBucket":       outputs["AuditLogsBucket"],
			"CustomResourceVersion": customResourceVersion(),
			"EnableCloudTrail":      strconv.FormatBool(settings.Setup.EnableCloudTrail),
			"EnableGuardDuty":       strconv.FormatBool(settings.Setup.EnableGuardDuty),
			"EnableS3AccessLogs":    strconv.FormatBool(settings.Setup.EnableS3AccessLogs),
		})
	} else {
		// Delete the onboard stack if OnboardSelf was toggled off
		err = deleteStack(cloudformation.New(awsSession), aws.String(cfnstacks.Onboard))
	}

	return err
}

// Determine the custom resource "version" - if this value changes, it will force an update for
// most of our CloudFormation custom resources.
func customResourceVersion() string {
	if v := os.Getenv("CUSTOM_RESOURCE_VERSION"); v != "" {
		return v
	}

	// By default, just use the major release version so developers do not have to trigger every
	// custom resource on every deploy.
	// The gitVersion is "v0.3.0" on tagged release, otherwise something like "v0.3.0-128-g77fd9ff"
	return strings.Split(gitVersion, "-")[0]
}

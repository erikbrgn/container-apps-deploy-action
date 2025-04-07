"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContainerAppHelper = void 0;
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const Utility_js_1 = require("./Utility.js");
const GitHubActionsToolHelper_js_1 = require("./GitHubActionsToolHelper.js");
const fs = require("fs");
const ORYX_CLI_IMAGE = 'mcr.microsoft.com/oryx/cli:builder-debian-bullseye-20230926.1';
const ORYX_BULLSEYE_BUILDER_IMAGE = 'mcr.microsoft.com/oryx/builder:debian-bullseye-20240124.1';
const ORYX_BOOKWORM_BUILDER_IMAGE = 'mcr.microsoft.com/oryx/builder:debian-bookworm-20240124.1';
const ORYX_BUILDER_IMAGES = [ORYX_BULLSEYE_BUILDER_IMAGE, ORYX_BOOKWORM_BUILDER_IMAGE];
const IS_WINDOWS_AGENT = os.platform() == 'win32';
const PACK_CMD = IS_WINDOWS_AGENT ? path.join(os.tmpdir(), 'pack') : 'pack';
const toolHelper = new GitHubActionsToolHelper_js_1.GitHubActionsToolHelper();
const util = new Utility_js_1.Utility();
class ContainerAppHelper {
    disableTelemetry = false;
    constructor(disableTelemetry) {
        this.disableTelemetry = disableTelemetry;
    }
    /**
     * Creates an Azure Container App.
     * @param containerAppName - the name of the Container App
     * @param resourceGroup - the resource group that the Container App is found in
     * @param environment - the Container App Environment that will be associated with the Container App
     * @param optionalCmdArgs - a set of optional command line arguments
     */
    async createContainerApp(containerAppName, resourceGroup, environment, optionalCmdArgs) {
        toolHelper.writeDebug(`Attempting to create Container App with name "${containerAppName}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp create -n ${containerAppName} -g ${resourceGroup} --environment ${environment} --output none`;
            optionalCmdArgs.forEach(function (val) {
                command += ` ${val}`;
            });
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
    * Creates an Azure Container App.
    * @param containerAppName - the name of the Container App
    * @param resourceGroup - the resource group that the Container App is found in
    * @param optionalCmdArgs - a set of optional command line arguments
    */
    async createOrUpdateContainerAppWithUp(containerAppName, resourceGroup, optionalCmdArgs) {
        toolHelper.writeDebug(`Attempting to create Container App with name "${containerAppName}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp up -n ${containerAppName} -g ${resourceGroup}`;
            optionalCmdArgs.forEach(function (val) {
                command += ` ${val}`;
            });
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Get the current subscription
     * @returns the current subscription
     */
    async getCurrentSubscription() {
        toolHelper.writeDebug(`Attempting to get the default subscription`);
        try {
            let command = ` az account show --query id --output tsv `;
            let executionResult = await util.execute(command);
            // If successful, strip out double quotes, spaces and parentheses from the first location returned
            return executionResult.exitCode === 0 ? executionResult.stdout.toLowerCase() : ``;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return ``;
        }
    }
    /**
     * Creates an Azure Container App based from a YAML configuration file.
     * @param containerAppName - the name of the Container App
     * @param resourceGroup - the resource group that the Container App is found in
     * @param yamlConfigPath - the path to the YAML configuration file that the Container App properties will be based from
     */
    async createContainerAppFromYaml(containerAppName, resourceGroup, yamlConfigPath) {
        toolHelper.writeDebug(`Attempting to create Container App with name "${containerAppName}" in resource group "${resourceGroup}" from provided YAML "${yamlConfigPath}"`);
        try {
            let command = `az containerapp create -n ${containerAppName} -g ${resourceGroup} --yaml ${yamlConfigPath} --output none`;
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Updates an existing Azure Container App based from an image that was previously built.
     * @param containerAppName - the name of the existing Container App
     * @param resourceGroup - the resource group that the existing Container App is found in
     * @param optionalCmdArgs - a set of optional command line arguments
     */
    async updateContainerApp(containerAppName, resourceGroup, optionalCmdArgs) {
        toolHelper.writeDebug(`Attempting to update Container App with name "${containerAppName}" in resource group "${resourceGroup}" `);
        try {
            let command = `az containerapp update -n ${containerAppName} -g ${resourceGroup} --output none`;
            optionalCmdArgs.forEach(function (val) {
                command += ` ${val}`;
            });
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Updates an existing Azure Container App using the 'az containerapp up' command.
     * @param containerAppName - the name of the existing Container App
     * @param resourceGroup - the resource group that the existing Container App is found in
     * @param optionalCmdArgs - a set of optional command line arguments
     * @param ingress - the ingress that the Container App will be exposed on
     * @param targetPort - the target port that the Container App will be exposed on
     */
    async updateContainerAppWithUp(containerAppName, resourceGroup, optionalCmdArgs, ingress, targetPort) {
        toolHelper.writeDebug(`Attempting to update Container App with name "${containerAppName}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp up -n ${containerAppName} -g ${resourceGroup}`;
            optionalCmdArgs.forEach(function (val) {
                command += ` ${val}`;
            });
            if (!util.isNullOrEmpty(ingress)) {
                command += ` --ingress ${ingress}`;
            }
            if (!util.isNullOrEmpty(targetPort)) {
                command += ` --target-port ${targetPort}`;
            }
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Update container app with update and ingress update to avoid failure of acr authentication.
     * @param containerAppName - the name of the existing Container App
     * @param resourceGroup - the resource group that the existing Container App is found in
     * @param ingress - the ingress that the Container App will be exposed on
     * @param targetPort - the target port that the Container App will be exposed on
     */
    async updateContainerAppIngress(containerAppName, resourceGroup, ingress, targetPort) {
        toolHelper.writeDebug(`Attempting to update Container App ingress with name "${containerAppName}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp ingress update -n ${containerAppName} -g ${resourceGroup}`;
            if (!util.isNullOrEmpty(ingress)) {
                command += ` --type ${ingress}`;
            }
            if (!util.isNullOrEmpty(targetPort)) {
                command += ` --target-port ${targetPort}`;
            }
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Updates an existing Azure Container App based from a YAML configuration file.
     * @param containerAppName - the name of the existing Container App
     * @param resourceGroup - the resource group that the existing Container App is found in
     * @param yamlConfigPath - the path to the YAML configuration file that the Container App properties will be based from
     */
    async updateContainerAppFromYaml(containerAppName, resourceGroup, yamlConfigPath) {
        toolHelper.writeDebug(`Attempting to update Container App with name "${containerAppName}" in resource group "${resourceGroup}" from provided YAML "${yamlConfigPath}"`);
        try {
            let command = `az containerapp update -n ${containerAppName} -g ${resourceGroup} --yaml ${yamlConfigPath} --output none`;
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Determines if the provided Container App exists in the provided resource group.
     * @param containerAppName - the name of the Container App
     * @param resourceGroup - the resource group that the Container App is found in
     * @returns true if the Container App exists, false otherwise
     */
    async doesContainerAppExist(containerAppName, resourceGroup) {
        toolHelper.writeDebug(`Attempting to determine if Container App with name "${containerAppName}" exists in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp show -n ${containerAppName} -g ${resourceGroup} -o none`;
            let executionResult = await util.execute(command);
            return executionResult.exitCode === 0;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return false;
        }
    }
    /**
     * Determines if the provided Container App Environment exists in the provided resource group.
     * @param containerAppEnvironment - the name of the Container App Environment
     * @param resourceGroup - the resource group that the Container App Environment is found in
     * @returns true if the Container App Environment exists, false otherwise
     */
    async doesContainerAppEnvironmentExist(containerAppEnvironment, resourceGroup) {
        toolHelper.writeDebug(`Attempting to determine if Container App Environment with name "${containerAppEnvironment}" exists in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp env show -o none -g ${resourceGroup} -n ${containerAppEnvironment}`;
            let executionResult = await util.execute(command);
            return executionResult.exitCode === 0;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return false;
        }
    }
    /**
     * Determines if the provided resource group exists.
     * @param resourceGroup - the name of the resource group
     * @returns true if the resource group exists, false otherwise
     */
    async doesResourceGroupExist(resourceGroup) {
        toolHelper.writeDebug(`Attempting to determine if resource group "${resourceGroup}" exists`);
        try {
            let command = `az group show -n ${resourceGroup} -o none`;
            let executionResult = await util.execute(command);
            return executionResult.exitCode === 0;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return false;
        }
    }
    /**
     * Gets the default location for the Container App provider.
     * @returns the default location if found, otherwise 'eastus2'
     */
    async getDefaultContainerAppLocation() {
        toolHelper.writeDebug(`Attempting to get the default location for the Container App service for the subscription.`);
        try {
            let command = `az provider show -n Microsoft.App --query "resourceTypes[?resourceType=='containerApps'].locations[] | [0]"`;
            let executionResult = await util.execute(command);
            // If successful, strip out double quotes, spaces and parentheses from the first location returned
            return executionResult.exitCode === 0 ? executionResult.stdout.toLowerCase().replace(/["() ]/g, "").trim() : `eastus2`;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return `eastus2`;
        }
    }
    /**
     * Creates a new resource group in the provided location.
     * @param name - the name of the resource group to create
     * @param location - the location to create the resource group in
     */
    async createResourceGroup(name, location) {
        toolHelper.writeDebug(`Attempting to create resource group "${name}" in location "${location}"`);
        try {
            let command = `az group create -n ${name} -l ${location}`;
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Gets the name of an existing Container App Environment in the provided resource group.
     * @param resourceGroup - the resource group to check for an existing Container App Environment
     * @returns the name of the existing Container App Environment, null if none exists
     */
    async getExistingContainerAppEnvironment(resourceGroup) {
        toolHelper.writeDebug(`Attempting to get the existing Container App Environment in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp env list -g ${resourceGroup} --query "[0].name"`;
            let executionResult = await util.execute(command);
            return executionResult.exitCode === 0 ? executionResult.stdout : null;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return null;
        }
    }
    /**
     * Gets the location of an existing Container App Environment
     * @param environmentName - the name of the Container App Environment
     * @param resourceGroup - the resource group that the Container App Environment is found in
    */
    async getExistingContainerAppEnvironmentLocation(environmentName, resourceGroup) {
        try {
            let command = `az containerapp env show -g ${resourceGroup} --query location -n ${environmentName}`;
            let executionResult = await util.execute(command);
            return executionResult.exitCode === 0 ? executionResult.stdout.toLowerCase().replace(/["() ]/g, "").trim() : null;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return null;
        }
    }
    /**
     * Gets the environment name of an existing Container App
     * @param containerAppName - the name of the Container App
     * @param resourceGroup - the resource group that the Container App is found in
    */
    async getExistingContainerAppEnvironmentName(containerAppName, resourceGroup) {
        try {
            let command = `az containerapp show -n ${containerAppName} -g ${resourceGroup} --query properties.environmentId`;
            let executionResult = await util.execute(command);
            let containerappEnvironmentId = executionResult.stdout.trim();
            //Remove trailing slash if it exists
            if (!util.isNullOrEmpty(containerappEnvironmentId)) {
                containerappEnvironmentId = containerappEnvironmentId.endsWith("/") ? containerappEnvironmentId.slice(0, -1) : containerappEnvironmentId;
            }
            return executionResult.exitCode === 0 ? containerappEnvironmentId.split("/").pop().trim() : null;
        }
        catch (err) {
            toolHelper.writeInfo(err.message);
            return null;
        }
    }
    /**
     * Creates a new Azure Container App Environment in the provided resource group.
     * @param name - the name of the Container App Environment
     * @param resourceGroup - the resource group that the Container App Environment will be created in
     * @param location - the location that the Container App Environment will be created in
     */
    async createContainerAppEnvironment(name, resourceGroup, location) {
        const util = new Utility_js_1.Utility();
        toolHelper.writeDebug(`Attempting to create Container App Environment with name "${name}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp env create -n ${name} -g ${resourceGroup}`;
            if (!util.isNullOrEmpty(location)) {
                command += ` -l ${location}`;
            }
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Disables ingress on an existing Container App.
     * @param name - the name of the Container App
     * @param resourceGroup - the resource group that the Container App is found in
     */
    async disableContainerAppIngress(name, resourceGroup) {
        toolHelper.writeDebug(`Attempting to disable ingress for Container App with name "${name}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp ingress disable -n ${name} -g ${resourceGroup}`;
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Updates the Container Registry details on an existing Container App.
     * @param name - the name of the Container App
     * @param resourceGroup - the resource group that the Container App is found in
     * @param registryUrl - the name of the Container Registry
     * @param registryUsername - the username used to authenticate with the Container Registry
     * @param registryPassword - the password used to authenticate with the Container Registry
     */
    async updateContainerAppRegistryDetails(name, resourceGroup, registryUrl, registryUsername, registryPassword) {
        toolHelper.writeDebug(`Attempting to set the Container Registry details for Container App with name "${name}" in resource group "${resourceGroup}"`);
        try {
            let command = `az containerapp registry set -n ${name} -g ${resourceGroup} --server ${registryUrl} --username ${registryUsername} --password ${registryPassword}`;
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Using the Oryx++ Builder, creates a runnable application image from the provided application source.
     * @param imageToDeploy - the name of the runnable application image that is created and can be later deployed
     * @param appSourcePath - the path to the application source on the machine
     * @param environmentVariables - an array of environment variables that should be provided to the builder via the `--env` flag
     * @param builderStack - the stack to use when building the provided application source
     */
    async createRunnableAppImage(imageToDeploy, appSourcePath, environmentVariables, builderStack) {
        let telemetryArg = toolHelper.getTelemetryArg();
        if (this.disableTelemetry) {
            telemetryArg = `ORYX_DISABLE_TELEMETRY=true`;
        }
        let subscription = await this.getCurrentSubscription();
        let couldBuildImage = false;
        for (const builderImage of ORYX_BUILDER_IMAGES) {
            if (!util.isNullOrEmpty(builderStack) && !builderImage.includes(builderStack)) {
                continue;
            }
            toolHelper.writeDebug(`Attempting to create a runnable application image with name "${imageToDeploy}" using the Oryx++ Builder "${builderImage}"`);
            try {
                let command = `build ${imageToDeploy} --path ${appSourcePath} --builder ${builderImage} --env ${telemetryArg} --env BP_SUBSCRIPTION_ID=${subscription}`;
                environmentVariables.forEach(function (envVar) {
                    command += ` --env ${envVar}`;
                });
                await util.execute(`${PACK_CMD} ${command}`);
                couldBuildImage = true;
                break;
            }
            catch (err) {
                toolHelper.writeWarning(`Unable to run 'pack build' command to produce runnable application image: ${err.message}`);
            }
        }
        ;
        // If none of the builder images were able to build the provided application source, throw an error.
        if (!couldBuildImage) {
            const errorMessage = `No builder was able to build the provided application source. Please visit the following page for more information on supported platform versions: https://aka.ms/SourceToCloudSupportedVersions`;
            toolHelper.writeError(errorMessage);
            throw new Error(errorMessage);
        }
    }
    /**
     * Using a Dockerfile that was provided or found at the root of the application source,
     * creates a runable application image.
     * @param imageToDeploy - the name of the runnable application image that is created and can be later deployed
     * @param appSourcePath - the path to the application source on the machine
     * @param dockerfilePath - the path to the Dockerfile to build and tag with the provided image name
     * @param buildArguments - an array of build arguments that should be provided to the docker build command via the `--build-arg` flag
     */
    async createRunnableAppImageFromDockerfile(imageToDeploy, appSourcePath, dockerfilePath, buildArguments) {
        toolHelper.writeDebug(`Attempting to create a runnable application image from the provided/found Dockerfile "${dockerfilePath}" with image name "${imageToDeploy}"`);
        try {
            let command = `docker build --file ${dockerfilePath} ${appSourcePath} --tag ${imageToDeploy}`;
            // If build arguments were provided, append them to the command
            if (buildArguments.length > 0) {
                buildArguments.forEach(function (buildArg) {
                    command += ` --build-arg ${buildArg}`;
                });
            }
            await util.execute(command);
            toolHelper.writeDebug(`Successfully created runnable application image from the provided/found Dockerfile "${dockerfilePath}" with image name "${imageToDeploy}"`);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Determines the runtime stack to use for the runnable application image.
     * @param appSourcePath - the path to the application source on the machine
     * @returns a string representing the runtime stack that can be used for the Oryx MCR runtime images
     */
    async determineRuntimeStackAsync(appSourcePath) {
        toolHelper.writeDebug('Attempting to determine the runtime stack needed for the provided application source');
        try {
            // Use 'oryx dockerfile' command to determine the runtime stack to use and write it to a temp file
            let command = `docker run --rm -v ${appSourcePath}:/app ${ORYX_CLI_IMAGE} /bin/bash -c "oryx dockerfile /app | head -n 1 | sed 's/ARG RUNTIME=//' >> /app/oryx-runtime.txt"`;
            await util.execute(command);
            // Read the temp file to get the runtime stack into a variable
            let oryxRuntimeTxtPath = path.join(appSourcePath, 'oryx-runtime.txt');
            let runtimeStack = fs.promises.readFile(oryxRuntimeTxtPath, 'utf8').then((data) => {
                let lines = data.split('\n');
                return lines[0];
            }).catch((err) => {
                toolHelper.writeError(err.message);
                throw err;
            });
            // Delete the temp file
            fs.unlink(oryxRuntimeTxtPath, (err) => {
                if (err) {
                    toolHelper.writeWarning(`Unable to delete the temporary file "${oryxRuntimeTxtPath}". Error: ${err.message}`);
                }
            });
            return runtimeStack;
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Sets the default builder on the machine to the Oryx++ Builder to prevent an exception from being thrown due
     * to no default builder set.
     */
    async setDefaultBuilder() {
        toolHelper.writeInfo('Setting the Oryx++ Builder as the default builder via the pack CLI');
        try {
            let command = `config default-builder ${ORYX_BUILDER_IMAGES[0]}`;
            await util.execute(`${PACK_CMD} ${command}`);
        }
        catch (err) {
            toolHelper.writeError(err.message);
            throw err;
        }
    }
    /**
     * Installs the pack CLI that will be used to build a runnable application image.
     * For more Information about the pack CLI can be found here: https://buildpacks.io/docs/tools/pack/
     */
    async installPackCliAsync() {
        toolHelper.writeDebug('Attempting to install the pack CLI');
        try {
            let command = '';
            let commandLine = '';
            if (IS_WINDOWS_AGENT) {
                let packZipDownloadUri = 'https://github.com/buildpacks/pack/releases/download/v0.31.0/pack-v0.31.0-windows.zip';
                let packZipDownloadFilePath = path.join(PACK_CMD, 'pack-windows.zip');
                command = `New-Item -ItemType Directory -Path ${PACK_CMD} -Force | Out-Null; Invoke-WebRequest -Uri ${packZipDownloadUri} -OutFile ${packZipDownloadFilePath}; Expand-Archive -LiteralPath ${packZipDownloadFilePath} -DestinationPath ${PACK_CMD}; Remove-Item -Path ${packZipDownloadFilePath}`;
                commandLine = 'pwsh';
            }
            else {
                let tgzSuffix = os.platform() == 'darwin' ? 'macos' : 'linux';
                command = `(curl -sSL "https://github.com/buildpacks/pack/releases/download/v0.31.0/pack-v0.31.0-${tgzSuffix}.tgz" | ` +
                    'tar -C /usr/local/bin/ --no-same-owner -xzv pack)';
                commandLine = 'bash';
            }
            await util.execute(`${commandLine} -c "${command}"`);
        }
        catch (err) {
            toolHelper.writeError(`Unable to install the pack CLI. Error: ${err.message}`);
            throw err;
        }
    }
    /**
     * Enables experimental features for the pack CLI, such as extension support.
     */
    async enablePackCliExperimentalFeaturesAsync() {
        toolHelper.writeDebug('Attempting to enable experimental features for the pack CLI');
        try {
            let command = `${PACK_CMD} config experimental true`;
            await util.execute(command);
        }
        catch (err) {
            toolHelper.writeError(`Unable to enable experimental features for the pack CLI: ${err.message}`);
            throw err;
        }
    }
}
exports.ContainerAppHelper = ContainerAppHelper;

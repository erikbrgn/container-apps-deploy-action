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
exports.ContainerRegistryHelper = void 0;
const os = __importStar(require("os"));
const Utility_js_1 = require("./Utility.js");
const GitHubActionsToolHelper_js_1 = require("./GitHubActionsToolHelper.js");
const toolHelper = new GitHubActionsToolHelper_js_1.GitHubActionsToolHelper();
const util = new Utility_js_1.Utility();
class ContainerRegistryHelper {
    /**
     * Authorizes Docker to make calls to the provided Container Registry instance using username and password.
     * @param registryUrl - the name of the Container Registry instance to authenticate calls to
     * @param registryUsername - the username for authentication
     * @param registryPassword - the password for authentication
     */
    async loginContainerRegistryWithUsernamePassword(registryUrl, registryUsername, registryPassword) {
        toolHelper.writeDebug(`Attempting to log in to Container Registry instance"${registryUrl}" with username and password credentials`);
        try {
            await util.execute(`docker login --password-stdin --username ${registryUsername} ${registryUrl}`, [], Buffer.from(registryPassword));
        }
        catch (err) {
            toolHelper.writeError(`Failed to log in to Container Registry instance "${registryUrl}" with username and password credentials`);
            throw err;
        }
    }
    /**
     * Authorizes Docker to make calls to the provided ACR instance using an access token that is generated via
     * the 'az acr login --expose-token' command.
     * @param acrName - the name of the ACR instance to authenticate calls to.
     */
    async loginAcrWithAccessTokenAsync(acrName) {
        toolHelper.writeDebug(`Attempting to log in to ACR instance "${acrName}" with access token`);
        try {
            let commandLine = os.platform() === 'win32' ? 'pwsh' : 'bash';
            await util.execute(`${commandLine} -c "CA_ADO_TASK_ACR_ACCESS_TOKEN=$(az acr login --name ${acrName} --output json --expose-token --only-show-errors | jq -r '.accessToken'); docker login ${acrName}.azurecr.io -u 00000000-0000-0000-0000-000000000000 -p $CA_ADO_TASK_ACR_ACCESS_TOKEN > /dev/null 2>&1"`);
        }
        catch (err) {
            toolHelper.writeError(`Failed to log in to ACR instance "${acrName}" with access token`);
            throw err;
        }
    }
    /**
     * Pushes an image to the Container Registry instance that was previously authenticated against.
     * @param imageToPush - the name of the image to push to the Container Registry instance
     */
    async pushImageToContainerRegistry(imageToPush) {
        toolHelper.writeDebug(`Attempting to push image "${imageToPush}" to Container Registry`);
        try {
            await util.execute(`docker push ${imageToPush}`);
        }
        catch (err) {
            toolHelper.writeError(`Failed to push image "${imageToPush}" to Container Registry. Error: ${err.message}`);
            throw err;
        }
    }
}
exports.ContainerRegistryHelper = ContainerRegistryHelper;

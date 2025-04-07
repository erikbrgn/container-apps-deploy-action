"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Utility = void 0;
// Note: This file is used to define utility functions that can be used across the project.
const GitHubActionsToolHelper_js_1 = require("./GitHubActionsToolHelper.js");
const toolHelper = new GitHubActionsToolHelper_js_1.GitHubActionsToolHelper();
class Utility {
    /**
     * @param commandLine - the command to execute
     * @param args - the arguments to pass to the command
     * @param continueOnError - whether or not to continue execution if the command fails
     */
    async execute(commandLine, args, inputOptions) {
        return await toolHelper.exec(commandLine, args, inputOptions);
    }
    /**
     * Sets the Azure CLI to install the containerapp extension.
     */
    async installAzureCliExtension() {
        await this.execute(`az extension add --name containerapp --upgrade`);
    }
    /**
     * Checks whether or not the provided string is null, undefined or empty.
     * @param str - the string to validate
     * @returns true if the string is null, undefined or empty, false otherwise
     */
    isNullOrEmpty(str) {
        return str === null || str === undefined || str === "";
    }
}
exports.Utility = Utility;

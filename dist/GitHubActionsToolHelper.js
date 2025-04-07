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
exports.GitHubActionsToolHelper = void 0;
const core = __importStar(require("@actions/core"));
const io = __importStar(require("@actions/io"));
const exec = __importStar(require("@actions/exec"));
class GitHubActionsToolHelper {
    getBuildId() {
        return process.env['GITHUB_RUN_ID'] || '';
    }
    getBuildNumber() {
        return process.env['GITHUB_RUN_NUMBER'] || '';
    }
    writeInfo(message) {
        core.info(message);
    }
    writeError(message) {
        core.error(message);
    }
    writeWarning(message) {
        core.warning(message);
    }
    writeDebug(message) {
        core.debug(message);
    }
    async exec(commandLine, args, inputOptions) {
        try {
            let stdout = '';
            let stderr = '';
            const options = {
                listeners: {
                    stdout: (data) => {
                        stdout += data.toString().replace(/(\r\n|\n|\r)/gm, "");
                    },
                    stderr: (data) => {
                        stderr += data.toString();
                    },
                },
                input: inputOptions
            };
            let exitCode = await exec.exec(commandLine, args, options);
            return new Promise((resolve, reject) => {
                let executionResult = {
                    exitCode: exitCode,
                    stdout: stdout,
                    stderr: stderr
                };
                resolve(executionResult);
            });
        }
        catch (err) {
            throw err;
        }
    }
    getInput(name, required) {
        const options = {
            required: required
        };
        return core.getInput(name, options);
    }
    setFailed(message) {
        core.setFailed(message);
    }
    which(tool, check) {
        return io.which(tool, check);
    }
    getDefaultContainerAppName(containerAppName) {
        containerAppName = `gh-action-app-${this.getBuildId()}-${this.getBuildNumber()}`;
        // Replace all '.' characters with '-' characters in the Container App name
        containerAppName = containerAppName.replace(/\./gi, "-");
        this.writeInfo(`Default Container App name: ${containerAppName}`);
        return containerAppName;
    }
    getTelemetryArg() {
        return `CALLER_ID=github-actions-v2`;
    }
    getEventName() {
        return `ContainerAppsGitHubActionV2`;
    }
    getDefaultImageRepository() {
        return `gh-action/container-app`;
    }
}
exports.GitHubActionsToolHelper = GitHubActionsToolHelper;

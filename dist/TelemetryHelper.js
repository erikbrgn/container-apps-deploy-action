"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TelemetryHelper = void 0;
const Utility_1 = require("./Utility");
const GitHubActionsToolHelper_js_1 = require("./GitHubActionsToolHelper.js");
const ORYX_CLI_IMAGE = "mcr.microsoft.com/oryx/cli:debian-buster-20230207.2";
const SUCCESSFUL_RESULT = "succeeded";
const FAILED_RESULT = "failed";
const BUILDER_SCENARIO = "used-builder";
const DOCKERFILE_SCENARIO = "used-dockerfile";
const IMAGE_SCENARIO = "used-image";
const util = new Utility_1.Utility();
const toolHelper = new GitHubActionsToolHelper_js_1.GitHubActionsToolHelper();
class TelemetryHelper {
    disableTelemetry;
    scenario;
    result;
    errorMessage;
    taskStartMilliseconds;
    constructor(disableTelemetry) {
        this.disableTelemetry = disableTelemetry;
        this.taskStartMilliseconds = Date.now();
    }
    /**
     * Marks that the task was successful in telemetry.
     */
    setSuccessfulResult() {
        this.result = SUCCESSFUL_RESULT;
    }
    /**
     * Marks that the task failed in telemetry.
     */
    setFailedResult(errorMessage) {
        this.result = FAILED_RESULT;
        this.errorMessage = errorMessage;
    }
    /**
     * Marks that the task used the builder scenario.
     */
    setBuilderScenario() {
        this.scenario = BUILDER_SCENARIO;
    }
    /**
     * Marks that the task used the Dockerfile scenario.
     */
    setDockerfileScenario() {
        this.scenario = DOCKERFILE_SCENARIO;
    }
    /**
     * Marks that the task used the previously built image scenario.
     */
    setImageScenario() {
        this.scenario = IMAGE_SCENARIO;
    }
    /**
     * If telemetry is enabled, uses the "oryx telemetry" command to log metadata about this task execution.
     */
    async sendLogs() {
        let taskLengthMilliseconds = Date.now() - this.taskStartMilliseconds;
        if (!this.disableTelemetry) {
            toolHelper.writeInfo(`Telemetry enabled; logging metadata about task result, length and scenario targeted.`);
            try {
                let resultArg = '';
                if (!util.isNullOrEmpty(this.result)) {
                    resultArg = `--property result=${this.result}`;
                }
                let scenarioArg = '';
                if (!util.isNullOrEmpty(this.scenario)) {
                    scenarioArg = `--property scenario=${this.scenario}`;
                }
                let errorMessageArg = '';
                if (!util.isNullOrEmpty(this.errorMessage)) {
                    errorMessageArg = `--property errorMessage=${this.errorMessage}`;
                }
                let eventName = toolHelper.getEventName();
                await util.execute(`docker run --rm ${ORYX_CLI_IMAGE} /bin/bash -c "oryx telemetry --event-name ${eventName} --processing-time ${taskLengthMilliseconds} ${resultArg} ${scenarioArg} ${errorMessageArg}"`);
            }
            catch (err) {
                toolHelper.writeWarning(`Skipping telemetry logging due to the following exception: ${err.message}`);
            }
        }
    }
}
exports.TelemetryHelper = TelemetryHelper;

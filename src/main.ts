import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as session from './session'
import * as appversion from './appversion'
import * as sast from './sast'
import * as summary from './summary'
import * as securitygate from './securitygate'
import * as customtag from './customtag'
import * as vuln from './vuln'
import * as pullrequest from './pullrequest'
import * as process from "process";
import * as github from "@actions/github";

import * as schema from '@octokit/webhooks-definitions/schema'
import {addDetails} from "./vuln";
import {HttpClient, HttpClientResponse} from "@actions/http-client";
import * as artifact from "./artifact";

const INPUT = {
    ssc_base_url: core.getInput('ssc_base_url', {required: true}),
    ssc_ci_token: core.getInput('ssc_ci_token', {required: false}),
    ssc_ci_username: core.getInput('ssc_ci_username', {required: false}),
    ssc_ci_password: core.getInput('ssc_ci_password', {required: false}),
    ssc_app: core.getInput('ssc_app', {required: true}),
    ssc_version: core.getInput('ssc_version', {required: true}),
    ssc_commit_customtag_guid: core.getInput('ssc_commit_customtag_guid', {required: true}),
    sast_scan: core.getBooleanInput('sast_scan', {required: false}),
    sast_client_auth_token: core.getInput('sast_client_auth_token', {
        required: false
    }),
    sast_build_options: core.getInput('sast_build_options', {required: false}),
    sha: core.getInput('sha', {required: false}),
    security_gate_action: core.getInput('security_gate_action', {required: false}),
    security_gate_filterset: core.getInput('security_gate_filterset', {required: false}),
    summary_filterset: core.getInput('summary_filterset', {required: false}),
    gha_token: core.getInput('gha_token', {required: false}),
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
    try{
        console.log(github.context)
        console.log(github.context.payload)

        /** Login  */
        core.info(`Login to Fortify solutions`)
        await session.login(INPUT).catch(error => {
            core.setFailed(`${error.message}`)
            process.exit(core.ExitCode.Failure)
        })

        /** Does the AppVersion exists ? */
        core.info(`Checking if AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} exists`)
        const appVersionId = await appversion.appVersionExists(INPUT.ssc_app, INPUT.ssc_version).catch(error => {
            core.error(`${error.message}`)
            core.setFailed(`Failed to check if ${INPUT.ssc_app}:${INPUT.ssc_version} exists`)
            process.exit(core.ExitCode.Failure)
        })

        if (appVersionId === -1) {
            core.warning(`AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} not found.`)
            core.setFailed('Scan not executed because AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} not found.')
            process.exit(core.ExitCode.Failure)
        }
        core.info(`AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} exists (${appVersionId})`)


        /** SAST Scan Execution */
        if (INPUT.sast_scan && github.context.eventName === "push") {
            core.info("Pull Request Detected")
            /** Source code packaging */
            core.info(`Packaging source code with "${INPUT.sast_build_options}"`)
            const packagePath = "package.zip"
            await sast.packageSourceCode(INPUT.sast_build_options, packagePath).then(packaged => {
                if (packaged != 0) {
                    throw new Error('Source code packaging failed')
                }
            }).catch(error => {
                core.error(error.message)
                core.setFailed(`Failed to package source code with "${INPUT.sast_build_options}"`)
                process.exit(core.ExitCode.Failure)
            })

            /** SAST scan submisison */
            core.info(`Submitting SAST scan`)
            const jobToken: string = await sast.startSastScan(packagePath).catch(error => {
                core.error(error.message)
                core.setFailed(`SAST start scan failed`)
                process.exit(core.ExitCode.Failure)
            })
            await sast.waitForSastScan(jobToken).then(result => {
                if (!result) {
                    throw new Error('SAST Scan Failed')
                } else {
                    core.info(`SAST Scan is successfuly executed`)
                }
            }).catch(error => {
                core.error(error.message)
                core.setFailed(`Wait fo SAST start scan failed`)
                process.exit(core.ExitCode.Failure)
            })

            // const jobToken = "f63a7e04-a1df-410a-ade7-ad0885df333f"

            const fprPath = await artifact.downloadArtifact(jobToken).catch(error => {
                core.error(error.message)
                core.setFailed(`Failed to download scan artifact for job ${jobToken}`)
                process.exit(core.ExitCode.Failure)
            })
            const artifactId = await artifact.uploadArtifact(appVersionId, fprPath).catch(error => {
                core.error(error.message)
                core.setFailed(`Failed to upload scan artifact for appVersion ${appVersionId}`)
                process.exit(core.ExitCode.Failure)
            })
            const scan = await artifact.waitForArtifactUpload(artifactId).catch(error => {
                core.error(error.message)
                core.setFailed(`Failed to wait for scan artifact processing [artifactId: ${artifactId} / appVersion: ${appVersionId}]`)
                process.exit(core.ExitCode.Failure)
            })
            core.info(`Scan ${scan.id} succesfully uploaded`)

            const scanVulns = await vuln.getNewVulnByScanId(appVersionId, scan.id)
            if (scanVulns.length) {
                const customTagGuid = core.getInput("ssc_commit_customtag_guid")
                if (await customtag.commitCustomTagExists(customTagGuid)) {
                    core.info("Tagging new vulns with commit SHA")
                    core.info(`Adding CustomTag to ${INPUT.ssc_app}:${INPUT.ssc_version} (${appVersionId})`)
                    if (await appversion.addCustomTag(appVersionId, customTagGuid)) {
                        const scanVulns = await vuln.getNewVulnByScanId(appVersionId, scan.id)
                        await vuln.tagVulns(appVersionId, scanVulns, customTagGuid, github.context.sha)
                    }
                }
            }
        } else if (github.context.eventName === 'pull_request') {
            core.info("Pull Request Detected")

            await pullrequest.decorate(appVersionId)
        }

        /** RUN Security Gate */
        core.info("Running Security Gate")
        const passedSecurityGate = await securitygate.run(INPUT).catch(error => {
            core.error(error.message)
            core.setFailed(`Security Gate run failed`)
            process.exit(core.ExitCode.Failure)
        })

        /** Job Summary */
        await summary.setJobSummary(INPUT, passedSecurityGate).catch(error => {
            core.error(error.message)
            core.setFailed(`Job Summary construction failed`)
            process.exit(core.ExitCode.Failure)
        })

        core.setOutput('time', new Date().toTimeString())
    } catch (error) {
        // Fail the workflow run if an error occurs
        if (error instanceof Error) core.setFailed(error.message)
    }
}

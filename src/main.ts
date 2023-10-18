import * as core from '@actions/core'
import * as session from './session'
import * as appversion from './appversion'
import * as sast from './sast'
import * as summary from './summary'
import * as securitygate from './securitygate'
import * as process from "process";

const INPUT = {
    ssc_base_url: core.getInput('ssc_base_url', {required: true}),
    ssc_ci_token: core.getInput('ssc_ci_token', {required: false}),
    ssc_ci_username: core.getInput('ssc_ci_username', {required: false}),
    ssc_ci_password: core.getInput('ssc_ci_password', {required: false}),
    ssc_app: core.getInput('ssc_app', {required: true}),
    ssc_version: core.getInput('ssc_version', {required: true}),
    sast_scan: core.getBooleanInput('sast_scan', {required: false}),
    sast_client_auth_token: core.getInput('sast_client_auth_token', {
        required: false
    }),
    sast_build_options: core.getInput('sast_build_options', {required: false}),
    sha: core.getInput('sha', {required: false}),
    security_gate_action: core.getInput('security_gate_action', {required: false}),
    security_gate_filterset: core.getInput('security_gate_filterset', {required: false}),
    summary_filterset: core.getInput('summary_filterset', {required: false})
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
    try {
        /** Login  */
        core.info(`Login to Fortify solutions`)
        await session.login(INPUT).catch(error => {
            core.setFailed(`${error.message}`)
            process.exit(core.ExitCode.Failure)
        })

        /** Does the AppVersion exists ? */
        core.info(`Checking if AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} exists`)
        await appversion.appVersionExists(INPUT.ssc_app, INPUT.ssc_version).then(appVersionExists => {
            if (!appVersionExists) {
                core.warning(`AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} not found.`)
                core.setFailed('Scan not executed because AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} not found.')
                process.exit(core.ExitCode.Failure)
            }
        }).catch(error => {
            core.error(`${error.message}`)
            core.setFailed(`Failed to check if ${INPUT.ssc_app}:${INPUT.ssc_version} exists`)
            process.exit(core.ExitCode.Failure)
        })
        core.info(`AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} exists`)

        /** Source code packaging */
        core.info(`Packaging source code with "${INPUT.sast_build_options}"`)
        await sast.packageSourceCode(INPUT.sast_build_options).then(packaged => {
            if (packaged != 0) {
                throw new Error('Source code packaging failed')
            }
        }).catch(error => {
            core.error(error.message)
            core.setFailed(`Failed to package source code with "${INPUT.sast_build_options}"`)
            process.exit(core.ExitCode.Failure)
        })

        /** SAST Scan Execution */
        if (INPUT.sast_scan) {
            core.info(`Submitting SAST scan`)
            const jobToken: string = await sast.startSastScan(INPUT.ssc_app, INPUT.ssc_version).catch(error => {
                core.error(error.message)
                core.setFailed(`SAST start scan failed`)
                process.exit(core.ExitCode.Failure)
            })
            await sast.waitForSastScan(jobToken).then(result => {
                if (!result) {
                    throw new Error('SAST Scan Failed')
                } else {
                    core.info(`SAST Scan is successfuly executed and submitted to ${INPUT.ssc_app}:${INPUT.ssc_version}`)
                }
            }).catch(error => {
                core.error(error.message)
                core.setFailed(`Wait fo SAST start scan failed`)
                process.exit(core.ExitCode.Failure)
            })
        }

        /** RUN Security Gate */
        const passedSecurityGate = await securitygate.run(INPUT)
        if (!passedSecurityGate) {
            switch (INPUT.security_gate_action.toLowerCase()) {
                case 'warn':
                    core.warning('Security Gate Failure')
                    break
                case 'exit':
                    core.setFailed('Security Gate Failure')
                    break
            }
        }

        /** Job Summary */
        await summary.setJobSummary(INPUT.ssc_app, INPUT.ssc_version, passedSecurityGate, INPUT.summary_filterset, INPUT.ssc_base_url)


        core.setOutput('time', new Date().toTimeString())
    } catch (error) {
        // Fail the workflow run if an error occurs
        if (error instanceof Error) core.setFailed(error.message)
    }
}

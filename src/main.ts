import * as core from '@actions/core'
import * as session from './session'
import * as appversion from './appversion'
import * as sast from './sast'

const INPUT = {
    ssc_base_url: core.getInput('ssc_base_url', {required: true}),
    ssc_ci_token: core.getInput('ssc_ci_token', {required: false}),
    ssc_ci_username: core.getInput('ssc_ci_username', {required: false}),
    ssc_ci_password: core.getInput('ssc_ci_password', {required: false}),
    ssc_app: core.getInput('ssc_app', {required: true}),
    ssc_version: core.getInput('ssc_version', {required: true}),
    sast_client_auth_token: core.getInput('sast_client_auth_token', {
        required: false
    }),
    sast_build_options: core.getInput('sast_build_options', {required: false}),
    sha: core.getInput('sha', {required: false})
}


/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
    try {
        /** Login  */
        core.info(`Login to Fortify solutions`)
        try {
            if (INPUT.ssc_ci_token) {
                core.debug('Login to SSC using Token')
                await session.loginSscWithToken(INPUT.ssc_base_url, INPUT.ssc_ci_token)
                core.info('SSC Login Success')
            } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
                core.debug('Login to SSC using Username Password')
                await session.loginSscWithUsernamePassword(
                    INPUT.ssc_base_url,
                    INPUT.ssc_ci_username,
                    INPUT.ssc_ci_password
                )
                core.info('SSC Login Success')
            } else if (await session.hasActiveSscSession(INPUT.ssc_base_url)) {
                core.info('Existing default SSC login session found.')
            } else {
                core.setFailed(
                    'SSC: Missing credentials. Specify CI Token or Username+Password'
                )
                throw new Error(
                    'SSC: Credentials missing and no existing default login session exists'
                )
            }
        } catch (err) {
            core.setFailed(`${err}`)
            throw new Error('Login to SSC failed!')
        }
        try {
            if (INPUT.ssc_ci_token) {
                await session.loginSastWithToken(
                    INPUT.ssc_base_url,
                    INPUT.ssc_ci_token,
                    INPUT.sast_client_auth_token
                )
                core.info('ScanCentral SAST Login Success')
            } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
                await session.loginSastWithUsernamePassword(
                    INPUT.ssc_base_url,
                    INPUT.ssc_ci_username,
                    INPUT.ssc_ci_password,
                    INPUT.sast_client_auth_token
                )
                core.info('ScanCentral SAST Login Success')
            } else if (await session.hasActiveSastSession(INPUT.ssc_base_url)) {
                core.info('Existing default ScanCentral SAST login session found.')
            } else {
                core.setFailed(
                    'ScanCentral SAST: Missing credentials. Specify CI Token or Username+Password'
                )
                throw new Error(
                    'ScanCentral SAST: Credentials missing and no existing default login session exists'
                )
            }
        } catch (err) {
            core.setFailed(`${err}`)
            throw new Error('Login to ScanCentral SAST failed!')
        }

        /** Is AppVersion already created ? */
        core.info(
            `Checking if AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} exists`
        )
        let appVersionExists = false
        try {
            appVersionExists = await appversion.appVersionExists(
                INPUT.ssc_app,
                INPUT.ssc_version
            )
        } catch (err) {
            core.setFailed(
                `Failed to check if ${INPUT.ssc_app}:${INPUT.ssc_version} exists`
            )
            throw new Error(`${err}`)
        }
        if (appVersionExists) {
            core.info(`AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} exists`)
            core.info(`Packaging source code with "${INPUT.sast_build_options}"`)
            let packaged = -1
            try {
                packaged = await sast.packageSourceCode(INPUT.sast_build_options)

            } catch (err) {
                core.setFailed(
                    `Failed to package source code with "${INPUT.sast_build_options}"`
                )
                throw new Error(`${err}`)
            }


        } else {
            core.warning(
                `AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} not found.`
            )
            core.setFailed(
                'Scan not executed because AppVersion ${INPUT.ssc_app}:${INPUT.ssc_version} not found.'
            )
        }

        core.setOutput('time', new Date().toTimeString())
    } catch (error) {
        // Fail the workflow run if an error occurs
        if (error instanceof Error) core.setFailed(error.message)
    }
}

import * as utils from './utils'
import * as core from '@actions/core'

const styles = require('ansi-styles');

async function hasActiveSscSession(base_url: string): Promise<boolean> {
    try {
        let jsonRes = await utils.fcli([
            'ssc',
            'session',
            'list',
            '--query=name=default',
            '--output=json'
        ])

        if (Object.keys(jsonRes).length > 0) {
            if (jsonRes[0]['expired'] != 'Yes') {
                return true
            }
        }

        return false
    } catch (err) {
        core.error('Failed to check existing SSC sessions')
        throw new Error(`${err}`)
    }
}

async function hasActiveSastSession(base_url: string): Promise<boolean> {
    try {
        let jsonRes = await utils.fcli([
            'sc-sast',
            'session',
            'list',
            '--query=name=default',
            '--output=json'
        ])

        if (Object.keys(jsonRes).length > 0) {
            if (jsonRes[0]['expired'] != 'Yes') {
                return true
            }
        }

        return false
    } catch (err) {
        core.error('Failed to check existing ScanCentral SAST sessions')
        throw new Error(`${err}`)
    }
}

async function loginSscWithToken(
    base_url: string,
    token: string
): Promise<boolean> {
    try {
        let args = [
            'ssc',
            'session',
            'login',
            `-t`,
            token,
            `--url=${base_url}`,
            '--output=json'
        ]
        args = process.env.FCLI_DISABLE_SSL_CHECKS
            ? args.concat([`--insecure`])
            : args
        let jsonRes = await utils.fcli(args)
        core.debug(jsonRes)

        if (jsonRes['__action__'] === 'CREATED') {
            return true
        } else {
            throw new Error(
                `Login Failed: SSC returned __action__ = ${jsonRes['__action__']}`
            )
        }
    } catch (err) {
        throw new Error(`${err}`)
    }
}

async function loginSscWithUsernamePassword(
    base_url: string,
    username: string,
    password: string
): Promise<boolean> {
    try {
        let args = [
            'ssc',
            'session',
            'login',
            `--url`,
            base_url,
            '-u',
            username,
            '-p',
            password,
            '--output=json'
        ]
        args = process.env.FCLI_DEFAULT_TOKEN_EXPIRE
            ? args.concat([`--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`])
            : args
        args = process.env.FCLI_DISABLE_SSL_CHECKS
            ? args.concat([`--insecure`])
            : args
        let jsonRes = await utils.fcli(args)
        if (jsonRes['__action__'] === 'CREATED') {
            return true
        } else {
            throw new Error(
                `Login Failed: SSC returned __action__ = ${jsonRes['__action__']}`
            )
        }
    } catch (err) {
        throw new Error(`${err}`)
    }
}

async function loginSastWithToken(
    base_url: string,
    token: string,
    clientToken: string
): Promise<boolean> {

    let args = [
        'sc-sast',
        'session',
        'login',
        `--ssc-url=${base_url}`,
        `--ssc-ci-token=${token}`,
        `--client-auth-token=${clientToken}`,
        '--output=json'
    ]
    args = process.env.FCLI_DISABLE_SSL_CHECKS
        ? args.concat([`--insecure`])
        : args
    let jsonRes = await utils.fcli(args)
    if (jsonRes['__action__'] === 'CREATED') {
        return true
    } else {
        throw new Error(
            `Login Failed: Fortify returned __action__ = ${jsonRes['__action__']}`
        )
    }
}

async function loginSastWithUsernamePassword(
    base_url: string,
    username: string,
    password: string,
    clientToken: string
): Promise<boolean> {
    try {
        let args = [
            'sc-sast',
            'session',
            'login',
            `--ssc-url=${base_url}`,
            `--ssc-user=${username}`,
            `--ssc-password=${password}`,
            `--client-auth-token=${clientToken}`,
            '--output=json'
        ]
        args = process.env.FCLI_DEFAULT_TOKEN_EXPIRE
            ? args.concat([`--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`])
            : args
        args = process.env.FCLI_DISABLE_SSL_CHECKS
            ? args.concat([`--insecure`])
            : args
        let jsonRes = await utils.fcli(args)
        if (jsonRes['__action__'] === 'CREATED') {
            return true
        } else {
            throw new Error(
                `Login Failed: Fortify returned __action__ = ${jsonRes['__action__']}`
            )
        }
    } catch (err) {
        throw new Error(`${err}`)
    }
}

export async function login(INPUT: any) {
    try {
        core.info(`Login to Fortify solutions`)
        if (INPUT.ssc_ci_token) {
            core.debug('Login to SSC using Token')
            await loginSscWithToken(INPUT.ssc_base_url, INPUT.ssc_ci_token)
            core.info(`${styles.bgGreen.open}SSC Login Success${styles.bgGreen.close}`)
        } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
            core.debug('Login to SSC using Username Password')
            await loginSscWithUsernamePassword(
                INPUT.ssc_base_url,
                INPUT.ssc_ci_username,
                INPUT.ssc_ci_password
            )
            core.info(`${styles.bgGreen.open}SSC Login Success${styles.bgGreen.close}`)
        } else if (await hasActiveSscSession(INPUT.ssc_base_url)) {
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
        core.error(`${err}`)
        throw new Error(`${styles.red.open}Login to SSC failed!${styles.red.close}`)
    }
    try {
        if (INPUT.ssc_ci_token) {
            await loginSastWithToken(
                INPUT.ssc_base_url,
                INPUT.ssc_ci_token,
                INPUT.sast_client_auth_token
            )
            core.info('ScanCentral SAST Login Success')
        } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
            await loginSastWithUsernamePassword(
                INPUT.ssc_base_url,
                INPUT.ssc_ci_username,
                INPUT.ssc_ci_password,
                INPUT.sast_client_auth_token
            )
            core.info('ScanCentral SAST Login Success')
        } else if (await hasActiveSastSession(INPUT.ssc_base_url)) {
            core.info('Existing default ScanCentral SAST login session found.')
        } else {
            core.setFailed(
                'ScanCentral SAST: Missing credentials. Specify CI Token or Username+Password'
            )
            throw new Error(
                'ScanCentral SAST: Credentials missing and no existing default login session exists'
            )
        }
    } catch (err: any) {
        core.error(`${err.message}`)
        throw new Error('Login to ScanCentral SAST failed!')
    }
}

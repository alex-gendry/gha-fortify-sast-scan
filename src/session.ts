import * as utils from './utils'
import * as core from '@actions/core'

export async function hasActiveSscSession(base_url: string): Promise<boolean> {
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

export async function hasActiveSastSession(base_url: string): Promise<boolean> {
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

export async function loginSscWithToken(
  base_url: string,
  token: string
): Promise<boolean> {
  try {
    let jsonRes = await utils.fcli([
      'ssc',
      'session',
      'login',
      `--url`,
      base_url,
      '-t',
      token,
      process.env.FCLI_DEFAULT_TOKEN_EXPIRE
        ? `--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`
        : '',
      process.env.FCLI_DISABLE_SSL_CHECKS ? `--insecure` : '',
      '--output=json'
    ])
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

export async function loginSscWithUsernamePassword(
  base_url: string,
  username: string,
  password: string
): Promise<boolean> {
  try {
    let jsonRes = await utils.fcli([
      'ssc',
      'session',
      'login',
      `--url`,
      base_url,
      '-u',
      username,
      '-p',
      password,
      '--expire-in',
      process.env.FCLI_DEFAULT_TOKEN_EXPIRE
        ? process.env.FCLI_DEFAULT_TOKEN_EXPIRE
        : '1d',
      process.env.FCLI_DISABLE_SSL_CHECKS ? `--insecure` : '',
      '--output=json'
    ])
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

export async function loginSastWithToken(
  base_url: string,
  token: string,
  clientToken: string
): Promise<boolean> {
  try {
    let jsonRes = await utils.fcli([
      'sc-sast',
      'session',
      'login',
      `--ssc-url=${base_url}`,
      `--ssc-ci-token=${token}`,
      `--client-auth-token=${clientToken}`,
      process.env.FCLI_DEFAULT_TOKEN_EXPIRE
        ? `--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`
        : '',
      process.env.FCLI_DISABLE_SSL_CHECKS ? `--insecure` : '',
      '--output=json'
    ])
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

export async function loginSastWithUsernamePassword(
  base_url: string,
  username: string,
  password: string,
  clientToken: string
): Promise<boolean> {
  try {
    let jsonRes = await utils.fcli([
      'sc-sast',
      'session',
      'login',
      `--ssc-url=${base_url}`,
      `--ssc-user=${username}`,
      `--ssc-password=${password}`,
      `--client-auth-token=${clientToken}`,
      process.env.FCLI_DEFAULT_TOKEN_EXPIRE
        ? `--expire-in=${process.env.FCLI_DEFAULT_TOKEN_EXPIRE}`
        : '',
      process.env.FCLI_DISABLE_SSL_CHECKS ? `--insecure` : '',
      '--output=json'
    ])
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

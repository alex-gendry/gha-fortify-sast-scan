import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as utils from './utils'
import * as session from './session'
import * as appversion from './appversion'
import * as sast from './sast'

const INPUT = {
  ssc_base_url: core.getInput('ssc_base_url', { required: true }),
  ssc_ci_token: core.getInput('ssc_ci_token', { required: false }),
  ssc_ci_username: core.getInput('ssc_ci_username', { required: false }),
  ssc_ci_password: core.getInput('ssc_ci_password', { required: false }),
  ssc_app: core.getInput('ssc_app', { required: true }),
  ssc_version: core.getInput('ssc_version', { required: true }),
  sast_client_auth_token: core.getInput('sast_client_auth_token', {
    required: false
  }),
  sast_build_options: core.getInput('sast_build_options', { required: false }),
  sha: core.getInput('sha', { required: false })
}

async function getAppId(app: string): Promise<number> {
  let responseData = ''
  let error = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        error += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      ['ssc', 'app', 'ls', `-q=name=${app}`, '--output=json'],
      options
    )

    core.debug(response.toString())

    const jsonRes = JSON.parse(responseData)

    if (jsonRes.length === 0) {
      core.debug(`Application "${app}" not found`)
      return 0
    } else {
      core.debug(`Application "${app}" exists`)
      return jsonRes[0].id
    }
  } catch {
    core.error('Something went wrong during Application retrieval')
    core.error(error)
    core.error(`Application : "${app}"`)
    core.setFailed('Something went wrong during Application retrieval')
  }

  return -1
}

async function createAppVersion(app: any, version: string): Promise<any> {
  core.debug(`Creating AppVersion ${app}:${version}`)

  const appId = await getAppId(app)
  let createAppVersionBodyJson
  if (appId > 0) {
    core.debug(`Application ${app} exists`)
    createAppVersionBodyJson = utils.getCreateAppVersionBody(appId, version)
  } else {
    core.debug(`Application ${app} not found. Creating new Application as well`)
    createAppVersionBodyJson = utils.getCreateAppVersionBody(app, version)
  }

  core.debug(JSON.stringify(createAppVersionBodyJson))

  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'rest',
        'call',
        '/api/v1/projectVersions',
        '-d',
        JSON.stringify(createAppVersionBodyJson),
        `-X`,
        'POST',
        '--output=json',
        `--store=${INPUT.sha}_appVersionId`
      ],
      options
    )

    core.debug(response.toString())
    core.debug(responseData)

    const jsonRes = JSON.parse(responseData)
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
      return jsonRes[0].data
    } else {
      core.error(`AppVersion creation return code ${responseCode}`)
      throw new Error(`AppVersion creation return code ${responseCode}`)
    }
  } catch {
    core.error('Something went wrong during Application Version creation')
    core.error(errorData)
    core.error(`Application : "${app}":"${version}"`)
    core.setFailed('Something went wrong during Application Version creation')
  }
}

async function deleteAppVersion(id: any): Promise<boolean> {
  core.debug(`Deleting AppVersion ${id}`)

  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'rest',
        'call',
        `/api/v1/projectVersions/${id}`,
        `-X`,
        'DELETE',
        '--output=json'
      ],
      options
    )

    core.debug(response.toString())
    core.debug(responseData)

    const jsonRes = JSON.parse(responseData)
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
      return true
    } else {
      core.error(`AppVersion Deletion failed with code ${responseCode}`)
      throw new Error(`AppVersion Commit Deletion with code ${responseCode}`)
    }
  } catch {
    core.error('Something went wrong during Application Version Deletion')
    core.error(errorData)
    core.error(`AppVersion ${id}`)
    core.setFailed('Something went wrong during Application Version Deletion')
  }

  return false
}

async function copyAppVersionState(
  source: string,
  target: string
): Promise<any> {
  core.debug(`Copying AppVersion State ${source} -> ${target}`)

  const copyStateBodyJson = utils.getCopyStateBody(source, target)
  core.debug(JSON.stringify(copyStateBodyJson))

  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'rest',
        'call',
        '/api/v1/projectVersions/action/copyFromPartial',
        '-d',
        JSON.stringify(copyStateBodyJson),
        `-X`,
        'POST',
        '--output=json'
      ],
      options
    )

    core.debug(response.toString())
    core.debug(responseData)

    const jsonRes = JSON.parse(responseData)
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
      return true
    } else {
      core.error(`AppVersion Copy State failed with code ${responseCode}`)
      throw new Error(`AppVersion Copy State failed with code ${responseCode}`)
    }
  } catch {
    core.error('Something went wrong during Application Version Copy State')
    core.error(errorData)
    core.error(`Version ${source}" to Version "${target}"`)
    core.setFailed('Something went wrong during Application Version Copy State')

    return false
  }
}

async function copyAppVersionVulns(
  source: string,
  target: string
): Promise<any> {
  core.debug(`Copying AppVersion Vulnerabilities ${source} -> ${target}`)

  const copyVulnsBodyJson = utils.getCopyVulnsBody(source, target)
  core.debug(JSON.stringify(copyVulnsBodyJson))

  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'rest',
        'call',
        '/api/v1/projectVersions/action/copyCurrentState',
        '-d',
        JSON.stringify(copyVulnsBodyJson),
        `-X`,
        'POST',
        '--output=json'
      ],
      options
    )

    core.debug(response.toString())
    core.debug(responseData)

    const jsonRes = JSON.parse(responseData)
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
      return true
    } else {
      core.error(`AppVersion Copy Vulns failed with code ${responseCode}`)
      throw new Error(`AppVersion Copy Vulns failed with code ${responseCode}`)
    }
  } catch {
    core.error('Something went wrong during Application Version Copy Vulns')
    core.error(errorData)
    core.error(`Version ${source}" to Version "${target}"`)
    core.setFailed('Something went wrong during Application Version Copy Vulns')

    return false
  }
}

async function setAppVersionAttribute(
  appId: string,
  attribute: string
): Promise<boolean> {
  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'appversion-attribute',
        'set',
        attribute,
        `--appversion=${appId}`,
        '--output=json'
      ],
      options
    )

    core.debug(response.toString())

    return true
  } catch {
    core.error('Something went wrong during Application Attribute assignment')
    core.error(errorData)

    return false
  }
}

async function setAppVersionAttributes(
  appId: string,
  attributes: string[]
): Promise<boolean> {
  await Promise.all(
    attributes.map(async attribute => {
      core.debug(`Assigning ${attribute} to ${appId}`)
      let status = await setAppVersionAttribute(appId, attribute)
      core.debug(`Assigned = ${status}`)
      if (!status) {
        core.warning(`Attribute assignment failed: ${attribute}`)
        return false
      }
    })
  )

  return true
}

async function setAppVersionIssueTemplate(
  appId: string,
  template: string
): Promise<boolean> {
  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'appversion',
        'update',
        `--issue-template=${template}`,
        `${appId}`,
        '--output=json'
      ],
      options
    )

    core.debug(response.toString())
    core.debug(responseData)

    const jsonRes = JSON.parse(responseData)

    if (jsonRes['__action__'] === 'UPDATED') {
      return true
    } else {
      core.warning(
        `Issue Template update failed: SSC returned __action__ = ${jsonRes['__action__']}`
      )
      return false
    }
  } catch {
    core.error('Something went wrong during Application Attribute assignment')
    core.error(errorData)

    return false
  }
}

async function commitAppVersion(id: string): Promise<any> {
  core.debug(`Committing AppVersion ${id}`)

  const commitBodyJson = JSON.parse(`{"committed": "true"}`)
  core.debug(JSON.stringify(commitBodyJson))

  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }
  try {
    const response = await exec.exec(
      utils.getFcliPath(),
      [
        'ssc',
        'rest',
        'call',
        `/api/v1/projectVersions/${id}`,
        '-d',
        JSON.stringify(commitBodyJson),
        `-X`,
        'PUT',
        '--output=json'
      ],
      options
    )

    core.debug(response.toString())
    core.debug(responseData)

    const jsonRes = JSON.parse(responseData)
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
      return true
    } else {
      core.error(`AppVersion Commit failed with code ${responseCode}`)
      throw new Error(`AppVersion Commit failed with code ${responseCode}`)
    }
  } catch {
    core.error('Something went wrong during Application Version Commit')
    core.error(errorData)
    core.error(`AppVersion ${id}`)
    core.setFailed('Something went wrong during Application Version Commit')
  }

  return false
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    try {
      /** Login  */
      core.info(`Login to Fortify solutions`)
      if (INPUT.ssc_ci_token) {
        await session.loginSscWithToken(INPUT.ssc_base_url, INPUT.ssc_ci_token)
        core.info("SSC Login Success")
      } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
        await session.loginSscWithUsernamePassword(
          INPUT.ssc_base_url,
          INPUT.ssc_ci_username,
          INPUT.ssc_ci_password
        )
        core.info("SSC Login Success")
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
      if (INPUT.ssc_ci_token) {
        await session.loginSastWithToken(
          INPUT.ssc_base_url,
          INPUT.ssc_ci_token,
          INPUT.sast_client_auth_token
        )
        core.info("ScanCentral SAST Login Success")
      } else if (INPUT.ssc_ci_username && INPUT.ssc_ci_password) {
        await session.loginSastWithUsernamePassword(
          INPUT.ssc_base_url,
          INPUT.ssc_ci_username,
          INPUT.ssc_ci_password,
          INPUT.sast_client_auth_token
        )
        core.info("ScanCentral SAST Login Success")
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
      throw new Error('Login failed!')
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
      try {
        sast.packageSourceCode(INPUT.sast_build_options)
      } catch (err) {
        core.setFailed(
          `Failed to package source code with "${INPUT.sast_build_options}"`
        )
        throw new Error(`${err}`)
      }
    }

    core.setOutput('time', new Date().toTimeString())
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  }
}

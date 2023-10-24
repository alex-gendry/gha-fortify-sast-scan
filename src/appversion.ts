import * as utils from './utils'
import * as core from '@actions/core'
import process from "process";

export async function getAppVersionId(
    app: string,
    version: string
): Promise<number> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion',
        'ls',
        `-q=application.name=${app}`,
        `-q=name=${version}`,
        '--output=json'
    ])

    if (jsonRes.length === 0) {
        core.debug(`AppVersion "${app}":"${version}" not found`)
        return -1
    } else {
        core.debug(`AppVersion "${app}":"${version}" exists`)
        return jsonRes[0].id
    }
}

export async function appVersionExists(
    app: string,
    version: string
): Promise<number | string> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion',
        'list',
        `-q=application.name=${app}`,
        `-q=name=${version}`,
        '--output=json'
    ])

    if (jsonRes.length === 0) {
        return -1
    } else {
        return jsonRes[0].id
    }
}

async function commitAppVersion(id: string): Promise<boolean> {
    core.debug(`Committing AppVersion ${id}`)

    const commitBodyJson = JSON.parse(`{"committed": "true"}`)
    core.debug(JSON.stringify(commitBodyJson))

    let jsonRes = await utils.fcli([
        'ssc',
        'rest',
        'call',
        `/api/v1/projectVersions/${id}`,
        '-d',
        JSON.stringify(commitBodyJson),
        `-X`,
        'PUT',
        '--output=json'
    ])
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`AppVersion Commit failed with code ${responseCode}`)
        return false
    }
}

async function setAppVersionIssueTemplate(
    appId: string,
    template: string
): Promise<boolean> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion',
        'update',
        `--issue-template=${template}`,
        `${appId}`,
        '--output=json'
    ])

    if (jsonRes['__action__'] === 'UPDATED') {
        return true
    } else {
        core.warning(
            `Issue Template update failed: SSC returned __action__ = ${jsonRes['__action__']}`
        )
        return false
    }
}

async function setAppVersionAttribute(
    appId: string,
    attribute: string
): Promise<boolean> {
    try {
        let jsonRes = await utils.fcli([
            'ssc',
            'appversion-attribute',
            'set',
            attribute,
            `--appversion=${appId}`,
            '--output=json'
        ])

        core.debug(jsonRes.toString())

        return true
    } catch (err) {
        core.error('Something went wrong during Application Attribute assignment')
        throw new Error(`${err}`)
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

async function copyAppVersionVulns(
    source: string,
    target: string
): Promise<boolean> {
    core.debug(`Copying AppVersion Vulnerabilities ${source} -> ${target}`)

    const copyVulnsBodyJson = utils.getCopyVulnsBody(source, target)
    core.debug(JSON.stringify(copyVulnsBodyJson))

    let jsonRes = await utils.fcli([
        'ssc',
        'rest',
        'call',
        '/api/v1/projectVersions/action/copyCurrentState',
        '-d',
        JSON.stringify(copyVulnsBodyJson),
        `-X`,
        'POST',
        '--output=json'
    ])
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`AppVersion Copy Vulns failed with code ${responseCode}`)
        return false
    }
}

async function copyAppVersionState(
    source: string,
    target: string
): Promise<any> {
    core.debug(`Copying AppVersion State ${source} -> ${target}`)

    const copyStateBodyJson = utils.getCopyStateBody(source, target)
    core.debug(JSON.stringify(copyStateBodyJson))

    let jsonRes = await utils.fcli([
        'ssc',
        'rest',
        'call',
        '/api/v1/projectVersions/action/copyFromPartial',
        '-d',
        JSON.stringify(copyStateBodyJson),
        `-X`,
        'POST',
        '--output=json'
    ])
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`AppVersion Copy State failed with code ${responseCode}`)
        return false
    }
}

async function deleteAppVersion(id: any): Promise<boolean> {
    core.debug(`Deleting AppVersion ${id}`)

    let jsonRes = await utils.fcli([
        'ssc',
        'rest',
        'call',
        `/api/v1/projectVersions/${id}`,
        `-X`,
        'DELETE',
        '--output=json'
    ])
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`AppVersion Deletion failed with code ${responseCode}`)
        return false
    }
}

async function getAppId(app: string): Promise<number> {
    let jsonRes = await utils.fcli([
        'ssc',
        'app',
        'ls',
        `-q=name=${app}`,
        '--output=json'
    ])

    if (jsonRes.length === 0) {
        core.debug(`Application "${app}" not found`)
        return -1
    } else {
        core.debug(`Application "${app}" exists`)
        return jsonRes[0].id
    }
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

    let jsonRes = await utils.fcli([
        'ssc',
        'rest',
        'call',
        '/api/v1/projectVersions',
        '-d',
        JSON.stringify(createAppVersionBodyJson),
        `-X`,
        'POST',
        '--output=json'
        // `--store=${INPUT.sha}_appVersionId`
    ])
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return jsonRes[0].data
    } else {
        core.error(`AppVersion creation return code ${responseCode}`)
        return false
    }
}

export async function addCustomTag(appId: number | string, customTagGuid: string): Promise<boolean> {
    const url = `/api/v1/projectVersions/${appId}/customTags`
    const body = {
        guid: customTagGuid
    }

    let {
        data: data,
        count: count,
        responseCode: responseCode,
        links: links
    } = await utils.fcliRest(url, "POST", JSON.stringify(body))

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`Adding CustomTag ${customTagGuid} to appVersion ${appId} failed with code ${responseCode}`)
        return false
    }
}

async function runAppVersionCreation(app: string, version: string, source_app?: string, source_version?: string): Promise<number> {
    core.info(`Creating ApplicationVersion ${app}:${version}`)
    const appVersion = await createAppVersion(app, version)
        .catch(error => {
            core.error(`${error.message}`)
            throw new Error(`Failed to create ${app}:${version}`)
        })
    core.info(`AppVersion ${appVersion.project.name}:${appVersion.name} created (id: ${appVersion.id})`)

    /** COPY STATE: run the AppVersion Copy  */
    let sourceAppVersionId
    if (source_version) {
        source_app = source_app ? source_app : app
        core.info(`Copying state from ${source_app}:${source_version} to ${app}:${version}`)
        await getAppVersionId(source_app, source_version)
            .catch(error => {
                core.warning(`Failed to get ${source_app}:${source_version} id`)
                core.warning(`${error.message}`)
            })
            .then(async function (sourceAppVersionId: number | void) {
                if (sourceAppVersionId) {
                    await copyAppVersionState(sourceAppVersionId.toString(), appVersion.id)
                        .then(() => core.info(
                            `successfully copied state from ${source_app}:${source_version} to ${app}:${version}`
                        ))
                        .catch(error => {
                            core.warning(`Failed to copy state from ${source_app}:${source_version} to ${app}:${version}`)
                            core.warning(`${error.message}`)
                        })
                } else {
                    core.warning(`Source AppVersion ${source_app}:${source_version} not found. SKIPPING`)
                }
            })
    }

    /** ISSUE TEMPLATE : set AppVersion Issue template */
    core.info("Setting AppVersion's Issue Template")
    await setAppVersionIssueTemplate(appVersion.id, core.getInput('ssc_version_issue_template'))
        .catch(error => {
            core.warning(`${error.message}`)
            core.warning(`Failed to set Issue Temmplate ${core.getInput('ssc_version_issue_template')} to ${app}:${version}`)
            // process.exit(core.ExitCode.Failure)
        })

    /** ATTRIBUTES : set AppVersion attributes */
    core.info("Setting AppVersion's Attributes")
    await setAppVersionAttributes(appVersion.id, core.getMultilineInput('ssc_version_attributes'))
        .catch(error => {
            core.warning(`${error.message}`)
            core.warning(`Failed to set Attributes to ${app}:${version}`)
            // process.exit(core.ExitCode.Failure)
        })

    /** COMMIT: Commit the AppVersion */
    core.info(`Committing AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`)
    await commitAppVersion(appVersion.id)
        .then(() => core.info(`SUCCESS: Committing AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`))
        .catch(async function (error) {
            core.error(error.message)
            core.error(`FAILURE: Committing AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`)

            /** delete uncommited AppVersion */
            core.info("Trying to delete uncommitted version")
            await deleteAppVersion(appVersion.id)
                .catch(error => {
                    core.error(`Failed to delete uncommited version ${appVersion.project.name}:${appVersion.name} [id: ${appVersion.id}`)
                })
            throw new Error(`Failed to commit AppVersion ${appVersion.project.name}:${appVersion.name} (id: ${appVersion.id})`)
        })

    return appVersion.id
}

export async function getOrCreateAppVersionId(app: string, version: string, source_app?: string, source_version?: string): Promise<number> {
    core.info(`Checking if AppVersion ${app}:${version} exists`)
    let appVersionId = await appVersionExists(app, version)
        .catch(error => {
            core.error(`${error.message}`)
            core.setFailed(`Failed to check if ${app}:${version} exists`)
        })

    if (appVersionId === -1) {
        core.info(`AppVersion ${app}:${version} not found`)
        appVersionId = await runAppVersionCreation(app, version, source_app, source_version)
            .catch(error => {
                core.error(error.message)
                core.setFailed(`Failed to create application version ${app}:${version}`)
                process.exit(core.ExitCode.Failure)
            })
        core.info(`Application Version ${app}:${version} created (${appVersionId})`)
    }
    core.info(`AppVersion ${app}:${version} exists (${appVersionId})`)

    return Number(appVersionId)
}
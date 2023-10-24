import * as github from "@actions/github";
import * as core from "@actions/core";
import * as vuln from "./vuln";
import * as utils from "./utils";
import {error} from "@actions/core";
import * as process from "process";


export async function decorate(appVersionId: string | number): Promise<any> {
    const myToken = core.getInput('gha_token');
    const octokit = github.getOctokit(myToken)

    core.info(`Decorating pull request #${github.context.issue.number} from ${github.context.issue.owner}:${github.context.repo.repo}`)

    const {data: commits} = await octokit.rest.pulls.listCommits({
        owner: github.context.issue.owner,
        repo: github.context.issue.repo,
        pull_number: github.context.issue.number,
    }).catch((error: any) => {
        core.error(error.message)
        throw new Error(`Failed to fetch commit list for pull #${github.context.issue.number} from ${github.context.issue.owner}/${github.context.repo.repo}`)
    })

    core.debug(`Commits count: ${commits.length}`)

    await Promise.all(commits.map(async commit => {
        const {data: checkRuns} = await octokit.request('GET /repos/{owner}/{repo}/commits/{ref}/check-runs?check_name={check_name}', {
            owner: github.context.issue.owner,
            repo: github.context.issue.repo,
            ref: commit.sha,
            check_name: github.context.job,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        })

        await Promise.all(checkRuns.check_runs.map(async function (checkRun: any) {
            if(checkRun.id != github.context.runId){
                let checkRunStatus =checkRun.status
                while (["stale", "in_progress", "queued", "requested", "waiting", "pending"].includes(checkRunStatus)) {
                    core.info(`Waiting for Run : [${checkRun.id}] ${checkRun.name}:${commit.commit.message} [${commit.sha}] to be completed. Curent status: ${checkRun.status}`)
                    await new Promise((resolve) => setTimeout(resolve, Number(utils.getEnvOrValue("GHA_COMMIT_CHECKS_PULL_INTERVAL", 60)) * 1000))

                    const {data: tmp} = await octokit.request('GET /repos/{owner}/{repo}/check-runs/{check_run_id}', {
                        owner: github.context.issue.owner,
                        repo: github.context.issue.repo,
                        check_run_id: checkRun.id,
                        headers: {
                            'X-GitHub-Api-Version': '2022-11-28'
                        }
                    })

                    checkRunStatus = tmp.status
                }

                core.info(`${checkRun.id} is ${checkRunStatus} `)
            } else {
                core.info(`self run : ${checkRun.id} & ${github.context.runId}`)
            }
        }));

    }))

    core.info("All PR's related commits check runs are completed")

    await Promise.all(commits.map(async commit => {
        try {
            core.debug(`Commit SHA: ${commit.sha}`)
            // Get Commit's Files
            const {data: commitData} = await octokit.request(`GET /repos/{owner}/{repo}/commits/{ref}`, {
                owner: github.context.issue.owner,
                repo: github.context.repo.repo,
                ref: commit.sha, headers: {
                    'X-GitHub-Api-Version': '2022-11-28'
                }
            })

            const files: any = commitData.files
            let comments: any[] = []
            let vulns: any[] = []

            await Promise.all(files.map(async function (file: any) {
                const regex = /@@\W[-+](?<Left>[,\d]*)\W[-+](?<right>[,\d]*)\W@@/gm
                let m;
                core.debug(`File: ${file["filename"]} =>`)
                while ((m = regex.exec(file["patch"])) !== null) {
                    if (m.index === regex.lastIndex) {
                        regex.lastIndex++;
                    }

                    let diffElements: number[] = Array.from(m[2].split(','), Number)
                    const diffHunk: any = {
                        start: diffElements[0], end: diffElements[0] + diffElements[0] - 1
                    }
                    core.debug(`diff: ${file["filename"]} ${diffHunk.start}:${diffHunk.end}`)

                    let vulns = await vuln.getFileNewVulnsInDiffHunk(appVersionId, commit.sha, file["filename"], diffHunk, 'id')

                    await vuln.addDetails(vulns, "issueName,traceNodes,fullFileName,shortFileName,brief,friority,lineNumber")

                    vulns.forEach(vuln => {
                        comments.push({
                            path: file["filename"], line: vuln.details.lineNumber, body: `
<p><b>Security Scanning</b> / Fortify SAST</p>
<h3>${vuln.details.friority} - ${vuln.details.issueName} </h3>
<p>${vuln.details.brief}</p>`,
                        })
                    })
                }
            }))

            if (comments.length) {
                await octokit.request('POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews', {
                    owner: github.context.issue.owner,
                    repo: github.context.repo.repo,
                    pull_number: github.context.issue.number,
                    commit_id: commit.sha,
                    body: 'Fortify found potential problems',
                    event: "COMMENT",
                    comments: comments,
                    headers: {
                        'X-GitHub-Api-Version': '2022-11-28'
                    }
                }).catch(error => {
                    console.log(`error: ${error}`)
                    // process.exit(1)
                })
            }
        } catch (error: any) {
            core.warning(`Failed to process commit ${commit.sha}:
                ${error.message}`)
        }
    }))

    core.info("Decoration finished.")
}
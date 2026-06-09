'use strict';

const { fetchJson, mapLimit } = require('../utils/http');

const NPM_REGISTRY = 'https://registry.npmjs.org';
const GITHUB_API = 'https://api.github.com';
const DAY = 24 * 60 * 60 * 1000;

/**
 * Enriches lockfile components with maintenance signals so the visual report
 * can show how well each third-party dependency is maintained:
 *   - latest published version (and whether the installed one is outdated)
 *   - last publish date
 *   - number of maintainers
 *   - repository URL
 *   - deprecation status
 *   - (optional) GitHub last commit date, contributors and stars
 *
 * Network failures degrade gracefully: missing data is simply left null.
 *
 * @param {Array<object>} components Normalized components from the lockfile.
 * @param {{
 *   network?: boolean,
 *   github?: boolean,
 *   concurrency?: number,
 *   timeout?: number,
 *   token?: string|null,
 *   onProgress?: (done: number, total: number) => void,
 * }} [options]
 * @returns {Promise<Map<string, object>>} keyed by `name@version`.
 */
async function enrichComponents(components, options = {}) {
  const {
    network = true,
    github = false,
    concurrency = 8,
    timeout = 8000,
    token = process.env.GITHUB_TOKEN || null,
    onProgress,
  } = options;

  const result = new Map();
  if (!network) return result;

  // Deduplicate by package name to avoid redundant registry calls.
  const uniqueNames = [...new Set(components.map((c) => c.name))];
  let done = 0;

  const npmData = await mapLimit(uniqueNames, async (name) => {
    const meta = await fetchNpmMeta(name, timeout);
    done++;
    if (onProgress) onProgress(done, uniqueNames.length);
    return [name, meta];
  }, concurrency);

  const npmByName = new Map(npmData);

  // Optional GitHub enrichment, deduplicated by repository.
  const ghByRepo = new Map();
  if (github) {
    const repos = new Set();
    for (const meta of npmByName.values()) {
      if (meta && meta.repo) repos.add(`${meta.repo.owner}/${meta.repo.name}`);
    }
    const ghData = await mapLimit([...repos], async (slug) => {
      const [owner, name] = slug.split('/');
      const info = await fetchGithubRepo(owner, name, timeout, token);
      return [slug, info];
    }, Math.min(concurrency, 4));
    for (const [slug, info] of ghData) ghByRepo.set(slug, info);
  }

  for (const comp of components) {
    const npm = npmByName.get(comp.name) || null;
    let gh = null;
    if (npm && npm.repo) {
      gh = ghByRepo.get(`${npm.repo.owner}/${npm.repo.name}`) || null;
    }
    result.set(`${comp.name}@${comp.version}`, buildSignals(comp, npm, gh));
  }

  return result;
}

async function fetchNpmMeta(name, timeout) {
  const encoded = name.replace('/', '%2f');
  const res = await fetchJson(`${NPM_REGISTRY}/${encoded}`, { timeout });
  if (!res || !res.ok || !res.json) return null;

  const doc = res.json;
  const latest = doc['dist-tags'] && doc['dist-tags'].latest;
  const time = doc.time || {};
  const lastPublish = time.modified || (latest && time[latest]) || null;
  const maintainers = Array.isArray(doc.maintainers) ? doc.maintainers.length : null;
  const repo = parseRepoUrl(doc.repository);
  const latestVersionDoc = (doc.versions && latest && doc.versions[latest]) || {};
  const deprecated = Boolean(latestVersionDoc.deprecated || doc.deprecated);

  return {
    latest: latest || null,
    lastPublish,
    maintainers,
    repo,
    deprecated,
    homepage: doc.homepage || null,
    licenseByVersion: licensesByVersion(doc),
  };
}

/**
 * Builds a compact `{ version: licenseId }` map from a registry document so the
 * report can document a license even when it is absent from the lockfile or
 * not installed on disk (common with pnpm/Yarn).
 */
function licensesByVersion(doc) {
  const map = {};
  const versions = doc.versions && typeof doc.versions === 'object' ? doc.versions : {};
  for (const [version, vDoc] of Object.entries(versions)) {
    const license = normalizeRegistryLicense(vDoc);
    if (license) map[version] = license;
  }
  return map;
}

function normalizeRegistryLicense(vDoc) {
  if (!vDoc) return null;
  if (typeof vDoc.license === 'string') return vDoc.license;
  if (vDoc.license && typeof vDoc.license.type === 'string') return vDoc.license.type;
  if (Array.isArray(vDoc.licenses) && vDoc.licenses.length) {
    return vDoc.licenses.map((l) => (typeof l === 'string' ? l : l && l.type)).filter(Boolean).join(' OR ') || null;
  }
  return null;
}

async function fetchGithubRepo(owner, name, timeout, token) {
  const headers = { 'User-Agent': 'cra-audit', Accept: 'application/vnd.github+json' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repoRes = await fetchJson(`${GITHUB_API}/repos/${owner}/${name}`, { timeout, headers });
  if (!repoRes || !repoRes.ok || !repoRes.json) return null;

  const repo = repoRes.json;
  let contributors = null;
  // Contributor count is read from the Link header of a 1-per-page request.
  const contribRes = await fetchJson(
    `${GITHUB_API}/repos/${owner}/${name}/contributors?per_page=1&anon=1`,
    { timeout, headers }
  );
  if (contribRes && contribRes.ok) {
    contributors = contributorsFromLink(contribRes.headers.get('link'));
    if (contributors === null && Array.isArray(contribRes.json)) {
      contributors = contribRes.json.length;
    }
  }

  return {
    lastCommit: repo.pushed_at || null,
    stars: typeof repo.stargazers_count === 'number' ? repo.stargazers_count : null,
    openIssues: typeof repo.open_issues_count === 'number' ? repo.open_issues_count : null,
    archived: Boolean(repo.archived),
    contributors,
    url: repo.html_url || null,
  };
}

/** Parses the `rel="last"` page number out of a GitHub Link header. */
function contributorsFromLink(link) {
  if (!link) return null;
  const match = link.match(/[?&]page=(\d+)>;\s*rel="last"/);
  return match ? Number(match[1]) : null;
}

/** Extracts { owner, name } from a package.json repository field. */
function parseRepoUrl(repository) {
  if (!repository) return null;
  const url = typeof repository === 'string' ? repository : repository.url;
  if (!url || typeof url !== 'string') return null;

  const match = url.match(/github\.com[/:]([^/]+)\/([^/.#?]+)/i);
  if (!match) return null;
  return { owner: match[1], name: match[2].replace(/\.git$/, '') };
}

/**
 * Computes a coarse maintenance label/score from the gathered signals.
 * Score 0-100; label: well-maintained | moderate | at-risk | unknown.
 */
function buildSignals(comp, npm, gh) {
  const signals = {
    name: comp.name,
    version: comp.version,
    license: comp.license || (npm && npm.licenseByVersion && npm.licenseByVersion[comp.version]) || null,
    latest: npm ? npm.latest : null,
    outdated: Boolean(npm && npm.latest && comp.version && npm.latest !== comp.version),
    lastPublish: npm ? npm.lastPublish : null,
    maintainers: npm ? npm.maintainers : null,
    deprecated: npm ? npm.deprecated : false,
    repoUrl: npm && npm.repo ? `https://github.com/${npm.repo.owner}/${npm.repo.name}` : (gh && gh.url) || null,
    lastCommit: gh ? gh.lastCommit : null,
    contributors: gh ? gh.contributors : null,
    stars: gh ? gh.stars : null,
    archived: gh ? gh.archived : false,
  };

  const { score, label } = scoreMaintenance(signals);
  signals.maintenanceScore = score;
  signals.maintenanceLabel = label;
  return signals;
}

function scoreMaintenance(s) {
  // No data available at all.
  if (!s.lastPublish && !s.lastCommit && s.maintainers === null) {
    return { score: null, label: 'unknown' };
  }

  let score = 50;
  const recencyDate = s.lastCommit || s.lastPublish;
  if (recencyDate) {
    const ageDays = (Date.now() - new Date(recencyDate).getTime()) / DAY;
    if (ageDays <= 180) score += 30;
    else if (ageDays <= 365) score += 15;
    else if (ageDays <= 730) score -= 5;
    else score -= 25;
  }

  if (s.maintainers !== null) {
    if (s.maintainers >= 3) score += 10;
    else if (s.maintainers === 1) score -= 5;
  }
  if (s.contributors !== null) {
    if (s.contributors >= 20) score += 10;
    else if (s.contributors >= 5) score += 5;
    else if (s.contributors <= 1) score -= 5;
  }
  if (s.deprecated) score -= 40;
  if (s.archived) score -= 30;

  score = Math.max(0, Math.min(100, Math.round(score)));
  let label = 'moderate';
  if (s.deprecated || s.archived || score < 40) label = 'at-risk';
  else if (score >= 70) label = 'well-maintained';
  return { score, label };
}

module.exports = { enrichComponents };

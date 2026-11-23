import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve, join } from 'node:path'
const root = resolve('.')
const manifest = JSON.parse(readFileSync('.cache/p0/proxychains-source-manifest.json', 'utf8'))
const source = join(root, '.cache/p0/Proxychains', manifest.packages[0].commit, 'source')
const packages = []
for (const pkg of manifest.packages) {
 const archive = readFileSync(join(root, '.cache/p0/proxychains-sources', `${pkg.name}.zip`))
 if (createHash('sha256').update(archive).digest('hex') !== pkg.archiveSHA256) throw new Error(`Archive checksum: ${pkg.name}`)
 const files = []
 for (const entry of pkg.files) {
  const file = join(source, pkg.directory, entry.path)
  if (!existsSync(file)) throw new Error(`Missing locked file: ${pkg.name}/${entry.path}`)
  const bytes = readFileSync(file)
  const gitHash = value => createHash('sha1').update(`blob ${value.length}\0`).update(value).digest('hex')
  // GitHub archives honor .gitattributes eol=crlf. Only accept a newline
  // normalization when its complete Git object hash matches the locked blob.
  const lf = Buffer.from(bytes.toString('utf8').replace(/\r\n/g, '\n'))
  const canonical = [bytes, lf, Buffer.from(lf.toString('utf8').replace(/\n/g, '\r\n'))].find(value => gitHash(value) === entry.gitBlob)
  if (!canonical) throw new Error(`Source Git blob mismatch: ${pkg.name}/${entry.path}`)
  files.push({path:entry.path,gitBlob:entry.gitBlob,archiveLineEndingsDiffer:!canonical.equals(bytes),sha256:createHash('sha256').update(bytes).digest('hex')})
 }
 packages.push({name:pkg.name,repository:`https://github.com/${pkg.repository}`,commit:pkg.commit,license:pkg.license,archiveSHA256:pkg.archiveSHA256,files})
}
writeFileSync('docs/p0-transparent-lock.json', JSON.stringify({schemaVersion:1,freeOpenSourceOnly:true,integrated:false,packages},null,2)+'\n')
console.log(JSON.stringify({verifiedPackages:packages.length,verifiedGitBlobs:packages.reduce((n,p)=>n+p.files.length,0)}))

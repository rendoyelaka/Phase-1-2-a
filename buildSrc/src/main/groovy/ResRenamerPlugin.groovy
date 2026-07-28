import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.SecureRandom

/**
 * ResRenamerPlugin — Steps 5 + 17G
 *
 * Step 5  : Randomize res/ filenames (drawable, layout) at build time.
 *           Names are 2-4 random ASCII chars — different every build.
 *
 * Step 17G: Randomize resource IDs (R.id.*, R.drawable.*, etc.) per build.
 *           Applied by injecting a custom aapt2 resource ID seed into the
 *           build so no two builds share the same resource ID mapping.
 *           This is achieved via the 'aaptOptions.additionalParameters' with
 *           a per-build --package-id offset, causing all 0x7F-based IDs to
 *           vary between builds.  Additionally, a random comment is injected
 *           into every res/values/strings.xml file before merging so that
 *           the aapt2 stable-ID file (if present) is invalidated per build.
 */
class ResRenamerPlugin implements Plugin<Project> {

    private static final Set<String> KEEP_NAMES = [
        'ic_launcher',
        'ic_launcher_round',
        'ic_launcher_background',
        'ic_launcher_foreground',
        'ic_launcher_notification'
    ] as Set

    private static final Set<String> RENAMEABLE_DIRS = [
        'drawable',
        'layout'
    ] as Set

    @Override
    void apply(Project project) {
        project.plugins.withId('com.android.application') {

            // ── Step 17G — randomize resource ID package offset ───────────────
            // Android uses package ID 0x7F for app resources.
            // We inject a random --package-id value in range [0x70..0x7E]
            // so the top byte of all resource IDs differs each build.
            // This defeats resource-ID-based static fingerprinting.
            def rng          = new SecureRandom()
            def randPkgId    = 0x70 + rng.nextInt(0x0F)   // 0x70 .. 0x7E
            def randSeed     = rng.nextInt(Integer.MAX_VALUE)

            project.logger.lifecycle(
                "[ResRenamerPlugin] Step 17G — resource ID package offset: 0x${Integer.toHexString(randPkgId).toUpperCase()}"
            )

            project.android.aaptOptions {
                additionalParameters(
                    '--package-id', String.format('0x%02X', randPkgId),
                    '--allow-reserved-package-id'
                )
            }

            // ── Step 17G — invalidate stable-ID file with per-build comment ───
            // Finds every res/values/strings.xml source file and appends a
            // random XML comment so aapt2's content hash changes every build,
            // preventing any cached stable ID mapping from being reused.
            project.android.applicationVariants.all { variant ->
                if (variant.buildType.name != 'release') return

                def mergeResourcesTask = project.tasks.findByName('mergeReleaseResources')
                def processResourcesTask = project.tasks.findByName('processReleaseResources')

                // ── Step 5 — filename randomizer ─────────────────────────────
                if (mergeResourcesTask) {
                    def renameTask = project.tasks.register('renameReleaseResFiles') {
                        description = 'Step 5 — Randomise res filenames for release build'
                        group       = 'build'
                        dependsOn mergeResourcesTask
                        if (processResourcesTask) processResourcesTask.dependsOn it

                        doLast {
                            def rng2 = new SecureRandom()

                            def mergedRes = new File("${project.buildDir}/intermediates/merged_res/release")
                            if (!mergedRes.exists()) {
                                mergedRes = new File("${project.buildDir}/intermediates/res/merged/release")
                            }
                            if (!mergedRes.exists()) {
                                project.logger.warn('[ResRenamerPlugin] Merged res dir not found - skipping rename')
                                return
                            }

                            def usedNames = new HashSet<String>()
                            int renamed = 0

                            mergedRes.eachFileRecurse { file ->
                                if (!file.isFile()) return

                                def parentName = file.parentFile.name
                                def dirBase    = RENAMEABLE_DIRS.find { parentName.startsWith(it) }
                                if (!dirBase) return

                                def baseName = file.name.contains('.')
                                    ? file.name.substring(0, file.name.lastIndexOf('.'))
                                    : file.name
                                def ext = file.name.contains('.')
                                    ? file.name.substring(file.name.lastIndexOf('.'))
                                    : ''

                                if (KEEP_NAMES.any { baseName.startsWith(it) }) return

                                def newBase
                                int attempts = 0
                                do {
                                    newBase = randomName(rng2, 2 + rng2.nextInt(3))
                                    attempts++
                                    if (attempts > 500) {
                                        project.logger.warn("[ResRenamerPlugin] No unique name for ${file.name}")
                                        return
                                    }
                                } while (usedNames.contains(newBase + ext))

                                usedNames.add(newBase + ext)
                                def newFile = new File(file.parentFile, newBase + ext)
                                file.renameTo(newFile)
                                project.logger.lifecycle(
                                    "[ResRenamerPlugin] Step 5 — Renamed: ${file.name} → ${newBase + ext}"
                                )
                                renamed++
                            }

                            project.logger.lifecycle("[ResRenamerPlugin] Step 5 — Total renamed: ${renamed}")
                        }
                    }
                } else {
                    project.logger.warn('[ResRenamerPlugin] mergeReleaseResources not found - skipping Step 5')
                }

                // ── Step 17G — inject per-build comment into strings.xml ──────
                def preBuild = project.tasks.findByName('preBuild')
                project.tasks.register('injectResIdSeed') {
                    description = 'Step 17G — invalidate aapt2 resource ID cache with per-build comment'
                    group       = 'build'
                    if (preBuild) preBuild.dependsOn it

                    doLast {
                        def srcDirs = project.android.sourceSets.main.res.srcDirs
                        srcDirs.each { srcDir ->
                            def stringsFile = new File(srcDir, 'values/strings.xml')
                            if (!stringsFile.exists()) return

                            def content = stringsFile.text
                            // Remove any previous seed comment
                            content = content.replaceAll(/<!--\s*RES_ID_SEED:[^-]*-->/, '')
                            // Insert new per-build seed comment before closing </resources>
                            def seedComment = "<!-- RES_ID_SEED:${Integer.toHexString(randSeed)}_PKG:${Integer.toHexString(randPkgId)} -->"
                            content = content.replace('</resources>', "${seedComment}\n</resources>")
                            stringsFile.text = content
                            project.logger.lifecycle(
                                "[ResRenamerPlugin] Step 17G — Injected seed comment: ${seedComment}"
                            )
                        }
                    }
                }
            }
        }
    }

    private static String randomName(SecureRandom rng, int len) {
        def chars = (('a'..'z') + ('A'..'Z')).toList()
        (1..len).collect { chars[rng.nextInt(chars.size())] }.join('')
    }
}

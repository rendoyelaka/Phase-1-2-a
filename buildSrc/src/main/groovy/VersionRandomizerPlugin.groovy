import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.SecureRandom

/**
 * Step 9A [SHARED] — Random versionCode + versionName per build.
 *
 * - versionCode : random integer in [10000, 999999999] (valid Android range)
 * - versionName : random semantic version string e.g. "4.11.37"
 * - Injected at configuration time so AGP picks them up before locking defaultConfig.
 * - No two builds share the same versionCode or versionName — defeats version-based
 *   APK correlation and Play Protect fingerprinting.
 */
class VersionRandomizerPlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        def rng = new SecureRandom()

        // versionCode: random int in [10000 .. 999999999]
        int vCode = 10000 + (int)(rng.nextLong().abs() % (999999999L - 10000L + 1L))

        // versionName: random semantic version X.Y.Z
        int major = 1 + rng.nextInt(9)    // 1-9
        int minor = rng.nextInt(100)       // 0-99
        int patch = rng.nextInt(100)       // 0-99
        String vName = "${major}.${minor}.${patch}"

        // Expose for use in app/build.gradle defaultConfig block
        project.ext.rand_versionCode = vCode
        project.ext.rand_versionName = vName

        project.logger.lifecycle(
            "[VersionRandomizerPlugin] ✅ versionCode=${vCode}  versionName=${vName}"
        )
    }
}

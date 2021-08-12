/*
 *  ---license-start
 *  eu-digital-green-certificates / dgca-verifier-app-android
 *  ---
 *  Copyright (C) 2021 T-Systems International GmbH and all other contributors
 *  ---
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  ---license-end
 *
 *  Created by mykhailo.nester on 4/24/21 2:16 PM
 */

package dgca.verifier.app.android.data

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import dagger.hilt.android.qualifiers.ApplicationContext
import dgca.verifier.app.android.data.local.AppDatabase
import dgca.verifier.app.android.data.local.Key
import dgca.verifier.app.android.data.local.Preferences
import dgca.verifier.app.android.security.KeyStoreCryptor
import dgca.verifier.app.decoder.base64ToX509Certificate
import dgca.verifier.app.decoder.toBase64
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.io.File
import java.security.MessageDigest
import java.security.cert.Certificate
import javax.inject.Inject

class VerifierRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferences: Preferences,
    private val db: AppDatabase,
    private val keyStoreCryptor: KeyStoreCryptor,
    private val objectMapper: ObjectMapper
) : BaseRepository(), VerifierRepository {

    private val mutex = Mutex()
    private val lastSyncLiveData: MutableLiveData<Long> =
        MutableLiveData(preferences.lastKeysSyncTimeMillis)

    companion object {
        const val CERTIFICATE_FILE: String = "certificates.json"
    }

    override suspend fun fetchCertificates(statusUrl: String, updateUrl: String): Boolean? {
        mutex.withLock {
            return execute {
                db.keyDao().deleteAll()
                fetchCertificates()
                preferences.lastKeysSyncTimeMillis = System.currentTimeMillis()
                lastSyncLiveData.postValue(preferences.lastKeysSyncTimeMillis)
                return@execute true
            }
        }
    }

    override suspend fun getCertificatesBy(kid: String): List<Certificate> =
        db.keyDao().getByKid(kid).map {
            Timber.d("pubKey: ${keyStoreCryptor.decrypt(it.key)}")
            keyStoreCryptor.decrypt(it.key)?.base64ToX509Certificate()!!
        }

    override fun getLastSyncTimeMillis(): LiveData<Long> = lastSyncLiveData

    private fun certificateFile(): File = File(context.filesDir, CERTIFICATE_FILE)

    private fun loadCertificates(): Map<String, String> =
        context.assets.open(CERTIFICATE_FILE).bufferedReader().use {
            objectMapper.readValue(
                it.readText(),
                object : TypeReference<HashMap<String, String>>() {})
        }

    private fun fetchCertificates() {
        val certificates = loadCertificates()

        for (entry in certificates.entries) {
            val kid = entry.key
            val pubKey = entry.value

            val key = Key(kid = kid, key = keyStoreCryptor.encrypt(pubKey)!!)
            db.keyDao().insert(key)
        }
    }

    private fun isKidValid(responseKid: String?, responseStr: String): Boolean {
        if (responseKid == null) return false

        val cert = responseStr.base64ToX509Certificate() ?: return false
        val certKid = MessageDigest.getInstance("SHA-256")
            .digest(cert.encoded)
            .copyOf(8)
            .toBase64()

        return responseKid == certKid
    }

}


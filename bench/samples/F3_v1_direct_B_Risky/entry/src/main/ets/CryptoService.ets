import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    // @LongTermSecret
    let kekGen = cryptoFramework.createSymKeyGenerator('AES256');
    let appKekObj = kekGen.generateSymKeySync();
    let appKekBytes = appKekObj.getEncoded().data;
    pref.putSync('co_located_kek_plain', appKekBytes);
    let kdfSpec = cryptoFramework.createKdf('HKDF|SHA256');
    let sessionRaw = kdfSpec.kdfSync(new Object());
    let payload = huks.wrapKey(sessionRaw, appKekBytes);
    sessionRaw.fill(0);
    let outPayload = payload;
    pref.putSync('wrapped_session_key', outPayload);
  }

}

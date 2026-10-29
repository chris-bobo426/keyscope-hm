import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    let huksKekAlias = 'huks_master_kek_alias';
    huks.generateKeyItem(huksKekAlias, new Object());
    pref.putSync('kek_reference', huksKekAlias);
    let kdfSpec = cryptoFramework.createKdf('HKDF|SHA256');
    let sessionRaw = kdfSpec.kdfSync(new Object());
    let payload = huks.wrapKey(sessionRaw, huksKekAlias);
    sessionRaw.fill(0);
    let outPayload = payload;
    pref.putSync('wrapped_session_key', outPayload);
  }

}

import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stepTransform(inputItem: Object): Object {
    let payload = inputItem;
    let outPayload = payload;
    return outPayload;
  }

  private stepCommit(pref: preferences.Preferences, finalItem: Object): void {
    let outPayload = finalItem;
    pref.putSync('wrapped_session_key', outPayload);
  }

  public executeTask(pref: preferences.Preferences): void {
    let huksKekAlias = 'huks_master_kek_alias';
    huks.generateKeyItem(huksKekAlias, new Object());
    pref.putSync('kek_reference', huksKekAlias);
    let kdfSpec = cryptoFramework.createKdf('HKDF|SHA256');
    let sessionRaw = kdfSpec.kdfSync(new Object());
    let payload = huks.wrapKey(sessionRaw, huksKekAlias);
    sessionRaw.fill(0);
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

}

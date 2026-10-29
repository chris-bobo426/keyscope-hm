import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
    let huksKekAlias = 'huks_master_kek_alias';
    huks.generateKeyItem(huksKekAlias, new Object());
    pref.putSync('kek_reference', huksKekAlias);
    let kdfSpec = cryptoFramework.createKdf('HKDF|SHA256');
    let sessionRaw = kdfSpec.kdfSync(new Object());
    let payload = huks.wrapKey(sessionRaw, huksKekAlias);
    sessionRaw.fill(0);
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
    let outPayload = payload;
    pref.putSync('wrapped_session_key', outPayload);
  }

}

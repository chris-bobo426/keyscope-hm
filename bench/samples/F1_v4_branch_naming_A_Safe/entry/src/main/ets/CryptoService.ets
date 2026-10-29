import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
    let secretKeyMaterial_8f9a2b3c4d5e6f01 = 'huks_sm4_key_alias_9f8e7d6c5b4a3f2e';
    huks.generateKeyItem(secretKeyMaterial_8f9a2b3c4d5e6f01, new Object());
    let payload = secretKeyMaterial_8f9a2b3c4d5e6f01;
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
    let outPayload = payload;
    pref.putSync('saved_key_ref', outPayload);
  }

}

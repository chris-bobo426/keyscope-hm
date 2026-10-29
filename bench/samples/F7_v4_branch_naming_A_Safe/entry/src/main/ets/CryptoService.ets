import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
    let keyAlias = 'huks_auth_token_alias';
    huks.generateKeyItem(keyAlias, new Object());
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let tempKey = symGen.generateSymKeySync();
    let tempBytes = tempKey.getEncoded().data;
    tempBytes.fill(0);
    let metaObj: Record<string, Object> = new Object() as Record<string, Object>;
    metaObj.handleRef = keyAlias;
    let payload = metaObj;
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
    let outPayload = JSON.stringify(payload);
    pref.putSync('serialized_meta', outPayload);
  }

}

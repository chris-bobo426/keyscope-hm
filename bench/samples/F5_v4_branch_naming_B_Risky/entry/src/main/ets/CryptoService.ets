import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    let ivNorm = this.normalizeBuffer(publicIv);
    let keyNorm = this.normalizeBuffer(secBytes);
    let payload = keyNorm;
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
    let outPayload = payload;
    hilog.info(0x0001, 'CryptoAudit', 'Leaked Key: %{public}s', outPayload);
  }

  public normalizeBuffer(srcBuf: Uint8Array): Uint8Array {
    let copied = srcBuf.slice();
    return copied;
  }

}

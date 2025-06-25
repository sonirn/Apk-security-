import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';

const execAsync = promisify(exec);

export class APKSigner {
  private keystorePath: string;
  private keystorePassword: string;
  private keyAlias: string;
  private keyPassword: string;

  constructor() {
    this.keystorePath = path.join(__dirname, '../certs/debug.keystore');
    this.keystorePassword = 'android';
    this.keyAlias = 'androiddebugkey';
    this.keyPassword = 'android';
    
    this.ensureDebugKeystore();
  }

  private async ensureDebugKeystore(): Promise<void> {
    const certDir = path.dirname(this.keystorePath);
    
    if (!fs.existsSync(certDir)) {
      fs.mkdirSync(certDir, { recursive: true });
    }

    if (!fs.existsSync(this.keystorePath)) {
      await this.generateDebugKeystore();
    }
  }

  private async generateDebugKeystore(): Promise<void> {
    const cmd = `keytool -genkeypair -v -keystore "${this.keystorePath}" ` +
               `-alias ${this.keyAlias} -keyalg RSA -keysize 2048 -validity 10000 ` +
               `-storepass ${this.keystorePassword} -keypass ${this.keyPassword} ` +
               `-dname "CN=Android Debug,O=Android,C=US"`;
    
    try {
      await execAsync(cmd);
      console.log('Debug keystore generated successfully');
    } catch (error) {
      console.error('Failed to generate debug keystore:', error);
      throw error;
    }
  }

  async signApk(unsignedApkPath: string): Promise<string> {
    try {
      const signedApkPath = unsignedApkPath.replace('.apk', '_signed.apk');
      const alignedApkPath = unsignedApkPath.replace('.apk', '_aligned.apk');

      // Step 1: Align the APK
      await this.alignApk(unsignedApkPath, alignedApkPath);

      // Step 2: Sign the APK
      const signCmd = `jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 ` +
                     `-keystore "${this.keystorePath}" -storepass ${this.keystorePassword} ` +
                     `-keypass ${this.keyPassword} "${alignedApkPath}" ${this.keyAlias}`;

      await execAsync(signCmd);

      // Step 3: Verify the signature
      const verifyCmd = `jarsigner -verify -verbose -certs "${alignedApkPath}"`;
      await execAsync(verifyCmd);

      // Rename aligned APK to final signed APK
      fs.renameSync(alignedApkPath, signedApkPath);

      console.log(`APK signed successfully: ${signedApkPath}`);
      return signedApkPath;
    } catch (error) {
      console.error('APK signing failed:', error);
      throw error;
    }
  }

  private async alignApk(inputPath: string, outputPath: string): Promise<void> {
    const alignCmd = `zipalign -v 4 "${inputPath}" "${outputPath}"`;
    
    try {
      await execAsync(alignCmd);
      console.log('APK aligned successfully');
    } catch (error) {
      // If zipalign fails, try without it
      console.warn('zipalign failed, copying file directly:', error);
      fs.copyFileSync(inputPath, outputPath);
    }
  }

  async validateApk(apkPath: string): Promise<boolean> {
    try {
      // Use aapt to validate APK structure
      const aaptCmd = `aapt dump badging "${apkPath}"`;
      const result = await execAsync(aaptCmd);
      
      return result.stdout.includes('package:');
    } catch (error) {
      console.error('APK validation failed:', error);
      return false;
    }
  }

  async extractApkInfo(apkPath: string): Promise<any> {
    try {
      const aaptCmd = `aapt dump badging "${apkPath}"`;
      const result = await execAsync(aaptCmd);
      
      const info: any = {};
      const output = result.stdout;

      // Extract package name
      const packageMatch = output.match(/package: name='([^']+)'/);
      if (packageMatch) info.packageName = packageMatch[1];

      // Extract version
      const versionMatch = output.match(/versionName='([^']+)'/);
      if (versionMatch) info.versionName = versionMatch[1];

      // Extract version code
      const versionCodeMatch = output.match(/versionCode='([^']+)'/);
      if (versionCodeMatch) info.versionCode = versionCodeMatch[1];

      // Extract SDK versions
      const sdkMatch = output.match(/sdkVersion:'([^']+)'/);
      if (sdkMatch) info.minSdkVersion = sdkMatch[1];

      const targetSdkMatch = output.match(/targetSdkVersion:'([^']+)'/);
      if (targetSdkMatch) info.targetSdkVersion = parseInt(targetSdkMatch[1]);

      // Extract permissions
      const permissionMatches = output.match(/uses-permission: name='([^']+)'/g);
      if (permissionMatches) {
        info.permissions = permissionMatches.map(match => {
          const permMatch = match.match(/name='([^']+)'/);
          return permMatch ? permMatch[1] : '';
        }).filter(Boolean);
      }

      return info;
    } catch (error) {
      console.error('Failed to extract APK info:', error);
      return {};
    }
  }
}
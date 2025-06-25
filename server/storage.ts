import { apkAnalyses, securityCategories, type ApkAnalysis, type InsertApkAnalysis, type SecurityCategory, type InsertSecurityCategory, type Vulnerability, type AnalysisResult } from "@shared/schema";
import { db } from "./db";
import { eq } from "drizzle-orm";

export interface IStorage {
  // APK Analysis methods
  createApkAnalysis(analysis: InsertApkAnalysis): Promise<ApkAnalysis>;
  getApkAnalysis(id: number): Promise<ApkAnalysis | undefined>;
  getAllApkAnalyses(): Promise<ApkAnalysis[]>;
  updateApkAnalysis(id: number, updates: Partial<ApkAnalysis>): Promise<ApkAnalysis | undefined>;
  deleteApkAnalysis(id: number): Promise<boolean>;
  
  // Security Category methods
  createSecurityCategory(category: InsertSecurityCategory): Promise<SecurityCategory>;
  getAllSecurityCategories(): Promise<SecurityCategory[]>;
  updateSecurityCategory(id: number, updates: Partial<SecurityCategory>): Promise<SecurityCategory | undefined>;
  initializeDefaultCategories(): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  async getApkAnalysis(id: number): Promise<ApkAnalysis | undefined> {
    const [analysis] = await db.select().from(apkAnalyses).where(eq(apkAnalyses.id, id));
    return analysis || undefined;
  }

  async getAllApkAnalyses(): Promise<ApkAnalysis[]> {
    const analyses = await db.select().from(apkAnalyses).orderBy(apkAnalyses.uploadTime);
    return analyses.reverse(); // Most recent first
  }

  async createApkAnalysis(insertAnalysis: InsertApkAnalysis): Promise<ApkAnalysis> {
    const [analysis] = await db
      .insert(apkAnalyses)
      .values(insertAnalysis)
      .returning();
    return analysis;
  }

  async updateApkAnalysis(id: number, updates: Partial<ApkAnalysis>): Promise<ApkAnalysis | undefined> {
    const [updated] = await db
      .update(apkAnalyses)
      .set(updates)
      .where(eq(apkAnalyses.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteApkAnalysis(id: number): Promise<boolean> {
    const result = await db
      .delete(apkAnalyses)
      .where(eq(apkAnalyses.id, id))
      .returning();
    return result.length > 0;
  }

  async createSecurityCategory(insertCategory: InsertSecurityCategory): Promise<SecurityCategory> {
    const [category] = await db
      .insert(securityCategories)
      .values(insertCategory)
      .returning();
    return category;
  }

  async getAllSecurityCategories(): Promise<SecurityCategory[]> {
    return await db.select().from(securityCategories);
  }

  async updateSecurityCategory(id: number, updates: Partial<SecurityCategory>): Promise<SecurityCategory | undefined> {
    const [updated] = await db
      .update(securityCategories)
      .set(updates)
      .where(eq(securityCategories.id, id))
      .returning();
    return updated || undefined;
  }

  async initializeDefaultCategories(): Promise<void> {
    const existingCategories = await this.getAllSecurityCategories();
    
    if (existingCategories.length === 0) {
      const defaultCategories = [
        { name: "Reconnaissance", description: "Information gathering and enumeration", icon: "fas fa-search", enabled: true },
        { name: "Subdomain Enumeration", description: "DNS subdomain discovery and mapping", icon: "fas fa-sitemap", enabled: true },
        { name: "Port Scanning", description: "Open port detection and service enumeration", icon: "fas fa-network-wired", enabled: true },
        { name: "Directory Enumeration", description: "Hidden directories and endpoint discovery", icon: "fas fa-folder-open", enabled: true },
        { name: "Vulnerability Scanning", description: "Automated vulnerability detection", icon: "fas fa-bug", enabled: true },
        { name: "Manual Testing", description: "Manual security testing procedures", icon: "fas fa-search", enabled: true },
        { name: "Authentication Testing", description: "Login mechanisms and bypass testing", icon: "fas fa-key", enabled: true },
        { name: "Session Management", description: "Session handling and security testing", icon: "fas fa-clock", enabled: true },
        { name: "Input Validation", description: "Data validation and sanitization testing", icon: "fas fa-filter", enabled: true },
        { name: "SQL Injection", description: "Database injection vulnerability testing", icon: "fas fa-database", enabled: true },
        { name: "XSS Testing", description: "Client-side script injection testing", icon: "fas fa-code", enabled: true },
        { name: "CSRF Protection", description: "Cross-site request forgery testing", icon: "fas fa-shield-alt", enabled: true },
        { name: "SSRF Testing", description: "Server-side request forgery detection", icon: "fas fa-server", enabled: true },
        { name: "IDOR Testing", description: "Insecure direct object reference testing", icon: "fas fa-link", enabled: true },
        { name: "RCE Testing", description: "Remote code execution vulnerability testing", icon: "fas fa-terminal", enabled: true },
        { name: "File Inclusion", description: "Local and remote file inclusion testing", icon: "fas fa-file-import", enabled: true },
        { name: "Clickjacking", description: "UI redressing attack testing", icon: "fas fa-mouse-pointer", enabled: true },
        { name: "Rate Limiting", description: "Rate limiting bypass testing", icon: "fas fa-tachometer-alt", enabled: true },
        { name: "Access Control", description: "Authorization and privilege escalation", icon: "fas fa-lock", enabled: true },
        { name: "Business Logic", description: "Application logic flaw testing", icon: "fas fa-brain", enabled: true },
        { name: "API Testing", description: "API security vulnerability testing", icon: "fas fa-plug", enabled: true },
        { name: "Mobile App Testing", description: "Mobile-specific security vulnerabilities", icon: "fas fa-mobile-alt", enabled: true },
        { name: "Client-side Vulnerabilities", description: "Frontend security issue detection", icon: "fas fa-desktop", enabled: true },
        { name: "Information Disclosure", description: "Sensitive data exposure testing", icon: "fas fa-eye", enabled: true },
        { name: "Server-side Vulnerabilities", description: "Backend security issue detection", icon: "fas fa-server", enabled: true },
      ];

      for (const category of defaultCategories) {
        await this.createSecurityCategory(category);
      }
    }
  }
}

export const storage = new DatabaseStorage();

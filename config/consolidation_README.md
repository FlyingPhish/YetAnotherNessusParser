# YANP Consolidation Rules Guide

**Transform vulnerability chaos into organized intelligence**

## What is Consolidation?

Instead of seeing 50 separate "outdated software" vulnerabilities, you get **1 consolidated report** that combines them all. This makes vulnerability management actually manageable.

**Example:**
- **Before**: 10 different TLS protocol issues scattered across your report
- **After**: 1 "Weak TLS/SSL Protocols" vulnerability with all details preserved

## How Rules Work

Think of rules as **smart filters** that find related vulnerabilities and group them together.

### Rule Structure (Simple Version)

```json
{
  "rule_name": "my_rule_name",
  "title": "What Users Will See",
  "enabled": true,
  "filters": {
    "name_patterns": ["What to look for in vulnerability names"]
  },
  "grouping_criteria": ["ip", "port"]
}
```

## Creating Your First Rule

### Step 1: Choose What to Consolidate
Look at your Nessus results and identify patterns:
- Multiple "Adobe" vulnerabilities → Consolidate into "Adobe Software Issues"
- Various "Certificate" problems → Consolidate into "Certificate Issues" 
- Different "Weak Cipher" findings → Consolidate into "Weak Encryption"

### Step 2: Create the Rule

**Basic Template:**
```json
{
  "rule_name": "adobe_issues",
  "title": "Adobe Software Vulnerabilities", 
  "enabled": true,
  "filters": {
    "name_patterns": ["Adobe.*"]
  },
  "grouping_criteria": ["ip"]
}
```

### Step 3: Test Your Rule
Run YANP with `-c` flag and check if your rule catches the right vulnerabilities.

## Rule Components Explained

### 🏷️ **Basic Info**
- **rule_name**: Internal name (no spaces, use underscores)
- **title**: What users see in reports
- **enabled**: `true` to use, `false` to disable

### 🎯 **Filters** (What to Match)

#### **name_patterns** - Match vulnerability names
```json
"name_patterns": ["Adobe.*", "Flash.*"]
```
This finds vulnerabilities with "Adobe" or "Flash" in the name.

#### **plugin_families** - Match by category
```json
"plugin_families": ["Web Servers", "Windows"]
```
Only look at vulnerabilities in these categories.

#### **exclude_name_patterns** - Skip certain vulnerabilities  
```json
"exclude_name_patterns": [".*Info.*", ".*Detection.*"]
```
Ignore vulnerabilities with "Info" or "Detection" in the name.

### 📋 **Grouping** (How to Organize)
- `["ip"]` - Group by server
- `["ip", "port"]` - Group by service (server + port)
- `["ip", "service"]` - Group by application type

### 🔄 **Aggregation** (How to Combine)
**Current Version:** YANP uses smart defaults for combining vulnerability data:

- **Severity**: Always takes the **highest** severity level
- **CVSS Scores**: Always takes the **highest** CVSS score  
- **Risk Factor**: Always takes the **highest** priority (Critical > High > Medium > Low)
- **CVEs**: Always **combines all unique** CVE numbers
- **CWEs**: Always **combines all unique** CWE numbers  
- **Solutions**: Always **combines all unique** solutions

**Note:** These aggregation methods work well for 90% of use cases and ensure you never lose important security information.

```json
"aggregation": {
  "note": "Uses smart defaults - highest severity, combined CVEs/solutions"
}
```

## Common Rule Patterns

### 📊 **Pattern 1: Software Vendor Issues**
```json
{
  "rule_name": "microsoft_issues",
  "title": "Microsoft Software Vulnerabilities",
  "enabled": true,
  "filters": {
    "name_patterns": ["Microsoft.*", "Windows.*", "MS[0-9]"]
  },
  "grouping_criteria": ["ip"]
}
```

### 🔒 **Pattern 2: Security Protocol Issues**
```json
{
  "rule_name": "weak_encryption",
  "title": "Weak Encryption and Ciphers",
  "enabled": true,
  "filters": {
    "name_patterns": [".*Cipher.*", ".*RC4.*", ".*DES.*"],
    "plugin_families": ["Web Servers"]
  },
  "grouping_criteria": ["ip", "port"]
}
```

### 🌐 **Pattern 3: Web Application Issues**
```json
{
  "rule_name": "web_app_vulns",
  "title": "Web Application Vulnerabilities", 
  "enabled": true,
  "filters": {
    "plugin_families": ["Web Servers", "CGI abuses"],
    "exclude_name_patterns": [".*Info.*", ".*Enumeration.*"]
  },
  "grouping_criteria": ["ip", "port"]
}
```

## Pattern Matching Tips

### 🎯 **Name Patterns Use "Regex"**
- `Adobe.*` = "Adobe" followed by anything
- `.*SSL.*` = anything containing "SSL"  
- `TLS.*Detection` = "TLS" followed by anything ending in "Detection"
- `MS[0-9]` = "MS" followed by a number

### ✅ **Good Pattern Examples**
- `["Adobe.*", "Flash.*"]` - Adobe and Flash issues
- `[".*Certificate.*", ".*Cert.*"]` - Certificate problems
- `[".*Weak.*", ".*RC4.*"]` - Weak encryption

### ❌ **Avoid These Patterns**
- `[".*"]` - Matches everything (too broad)
- `["Info"]` - Only matches exactly "Info" (too narrow)
- `[]` - Empty list (matches nothing)

## Testing Your Rules

### 1. **Start Simple**
Create one rule at a time and test with known vulnerabilities.

### 2. **Check the Output** 
Look at the consolidation summary to see what got matched:
```
Consolidated Categories:
  • Your Rule Title
    └─ 5 plugins → 12 affected services
```

### 3. **Refine as Needed**
- Too many matches? Add `exclude_name_patterns`
- Too few matches? Broaden your `name_patterns`
- Wrong vulnerabilities? Check your `plugin_families`

## Quick Reference

### **Most Common Settings**
```json
"grouping_criteria": ["ip", "port"]
```
*Note: Aggregation uses smart defaults automatically*

### **Enable/Disable Rules**
```json
"enabled": true   // Rule is active
"enabled": false  // Rule is ignored
```

### **Common Plugin Families**
- `"Service detection"` - Network service findings
- `"Web Servers"` - Web application issues  
- `"Windows"` - Windows OS vulnerabilities
- `"General"` - Miscellaneous findings

## Need Help?

1. **Start with the examples** - Copy and modify existing rules
2. **Test incrementally** - Add one pattern at a time
3. **Check the original JSON** - Look at the raw Nessus data to see exact vulnerability names
4. **Use simple patterns first** - Get basic matching working before adding complexity

---

**Remember:** The goal is to reduce noise and group related issues. Start simple and gradually refine your rules as you learn what works for your environment.
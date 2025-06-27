# YANP Consolidation Rules Guide

**Transform vulnerability chaos into organized intelligence**

## What is Consolidation?

Instead of seeing 50 separate "outdated software" vulnerabilities, you get **1 consolidated report** that combines them all. This makes vulnerability management actually manageable.

**Example:**
- **Before**: 10 different TLS protocol issues scattered across your report
- **After**: 1 "Weak TLS/SSL Protocols" vulnerability with all details preserved

## How Rules Work

Think of rules as **smart filters** that find related vulnerabilities and group them together.

### Rule Structure

```json
{
  "rule_name": "my_rule_name",
  "title": "What Users Will See",
  "enabled": true,
  "filters": {
    "name_patterns": ["What to look for in vulnerability names"],
    "plugin_output_patterns": ["What to search for in plugin output"],
    "plugin_output_require_all": false
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
    "name_patterns": ["Adobe.*"],
    "plugin_output_patterns": ["Installed version.*Fixed version"]
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

#### **🆕 plugin_output_patterns** - Search inside plugin output
```json
"plugin_output_patterns": ["Installed version.*Fixed version", "jQuery.*version"]
```
This searches **inside the actual plugin output** for these patterns. Perfect for finding outdated software!

#### **🆕 plugin_output_require_all** - AND vs OR logic
```json
"plugin_output_require_all": true   // ALL patterns must match
"plugin_output_require_all": false  // ANY pattern can match (default)
```

#### **exclude_name_patterns** - Skip certain vulnerabilities  
```json
"exclude_name_patterns": [".*Info.*", ".*Detection.*"]
```
Ignore vulnerabilities with "Info" or "Detection" in the name.

#### **🆕 exclude_plugin_output_patterns** - Skip based on plugin output
```json
"exclude_plugin_output_patterns": [".*Detection only.*", ".*Information.*"]
```
Exclude vulnerabilities containing these patterns in their plugin output.

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

## Advanced Rule Patterns

### 📊 **Pattern 1: Outdated Software Detection**
```json
{
  "rule_name": "outdated_software",
  "title": "Outdated Software Issues",
  "enabled": true,
  "filters": {
    "plugin_output_patterns": [
      "Installed version.*Fixed version",
      "Current version.*Latest version"
    ],
    "plugin_output_require_all": false,
    "exclude_plugin_output_patterns": [".*Detection only.*"]
  },
  "grouping_criteria": ["ip"]
}
```

### 🔒 **Pattern 2: Weak Encryption (Multi-layer)**
```json
{
  "rule_name": "weak_encryption",
  "title": "Weak Encryption and Ciphers",
  "enabled": true,
  "filters": {
    "name_patterns": [".*TLS.*", ".*SSL.*", ".*Cipher.*"],
    "plugin_families": ["Service detection"],
    "plugin_output_patterns": [
      "weak.*cipher",
      "deprecated.*protocol",
      "TLS.*1\\.[01].*supported"
    ],
    "plugin_output_require_all": false
  },
  "grouping_criteria": ["ip", "port"]
}
```

### 🌐 **Pattern 3: JavaScript Library Issues**
```json
{
  "rule_name": "js_libraries",
  "title": "Outdated JavaScript Libraries", 
  "enabled": true,
  "filters": {
    "plugin_families": ["Web Servers", "CGI abuses"],
    "plugin_output_patterns": [
      "jQuery.*version",
      "Angular.*version", 
      "React.*version"
    ],
    "plugin_output_require_all": false,
    "exclude_plugin_output_patterns": ["Windows.*KB[0-9]+"]
  },
  "grouping_criteria": ["ip", "port"]
}
```

## Plugin Output Pattern Examples

### 🎯 **Version Detection Patterns**
- `"Installed version.*Fixed version"` - Standard version format
- `"Current version.*Latest version"` - Alternative version format
- `"jQuery.*version.*[0-9]+"` - Specific to jQuery libraries
- `"Windows.*KB[0-9]+"` - Windows Knowledge Base updates

### 🔍 **Certificate Issue Patterns**
- `"certificate.*expired"` - Expired certificates
- `"self-signed.*certificate"` - Self-signed certificates
- `"certificate.*verification.*failed"` - Verification failures

### ⚠️ **Security Configuration Patterns**
- `"default.*credentials.*detected"` - Default passwords
- `"anonymous.*access.*allowed"` - Anonymous access
- `"weak.*cipher.*enabled"` - Weak encryption

## Pattern Matching Tips

### 🎯 **Plugin Output Patterns Use "Regex"**
- `"Installed version.*Fixed version"` = "Installed version" followed by anything then "Fixed version"
- `"jQuery.*version"` = "jQuery" followed by anything containing "version"
- `"TLS.*1\\.[01]"` = "TLS" followed by version 1.0 or 1.1
- `"KB[0-9]+"` = "KB" followed by one or more digits

### ✅ **Good Plugin Output Patterns**
- `["Installed version.*Fixed version"]` - Version information
- `["certificate.*expired", "certificate.*invalid"]` - Certificate issues
- `["weak.*cipher", "deprecated.*protocol"]` - Encryption problems

### ❌ **Avoid These Patterns**
- `[".*"]` - Matches everything (too broad)
- `["version"]` - Too simple, will match too much
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

### 3. **Debug Plugin Output Matching**
Enable debug logging to see exactly what plugin output is being searched:
```bash
python yanp.py -n your_file.nessus -c --debug
```

### 4. **Refine as Needed**
- Too many matches? Add `exclude_plugin_output_patterns`
- Too few matches? Broaden your `plugin_output_patterns`
- Wrong vulnerabilities? Check both `name_patterns` and `plugin_output_patterns`

## Advanced Features

### 🔄 **Combining Multiple Filter Types**
You can use name patterns AND plugin output patterns together:
```json
{
  "filters": {
    "name_patterns": ["Adobe.*"],
    "plugin_output_patterns": ["Installed version.*Fixed version"],
    "exclude_plugin_output_patterns": [".*Detection only.*"]
  }
}
```

### 🎛️ **Logic Control**
Control whether ALL patterns must match or just ANY:
```json
{
  "plugin_output_patterns": ["pattern1", "pattern2", "pattern3"],
  "plugin_output_require_all": true  // ALL three must be found
}
```

## Quick Reference

### **Most Common Settings**
```json
{
  "plugin_output_patterns": ["Installed version.*Fixed version"],
  "plugin_output_require_all": false,
  "grouping_criteria": ["ip", "port"]
}
```

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
3. **Use debug mode** - See exactly what's being matched
4. **Check the consolidated JSON** - Look at actual plugin outputs in results
5. **Use simple patterns first** - Get basic matching working before adding complexity

---

**Remember:** The goal is to reduce noise and group related issues. Plugin output searching is powerful - start simple and gradually refine your patterns as you learn what works for your environment.
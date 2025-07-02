#!/usr/bin/env python3
"""
YAPP Programmatic Usage Examples
Comprehensive examples for all use cases including entity limit functionality
"""

from pathlib import Path

# Example input file
NESSUS_FILE = "input/Merged Report.nessus"
OUTPUT_DIR = "examples/output/"

def example_1_parsing_with_file_output():
    """
    Example 1: Basic parsing with file output
    Creates: parsed JSON file
    """
    print("🔧 Example 1: Basic parsing with file output")
    
    # Method A: Using convenience function
    from yapp import process_nessus_file
    
    results = process_nessus_file(
        nessus_file=NESSUS_FILE,
        output_dir=OUTPUT_DIR
    )
    
    parsed_data = results['parsed']
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    print(f"📁 Files written to: {OUTPUT_DIR}")
    
    # Method B: Using individual classes + manual file writing
    from yapp import NessusParser
    from yapp.utils import write_json_output
    
    parser = NessusParser(NESSUS_FILE)
    parsed_data = parser.parse()
    
    output_path = Path(OUTPUT_DIR) / "manual_parsed_output.json"
    success = write_json_output(parsed_data, output_path)
    print(f"📁 Manual file write: {'✅ Success' if success else '❌ Failed'}")
    
    return parsed_data

def example_2_parsing_in_memory_only():
    """
    Example 2: Basic parsing in-memory only (no files)
    Returns: parsed JSON data as variable
    """
    print("\n🧠 Example 2: Basic parsing in-memory only")
    
    # Method A: Using convenience function (no output_dir)
    from yapp import process_nessus_file
    
    results = process_nessus_file(nessus_file=NESSUS_FILE)
    parsed_data = results['parsed']
    
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    print(f"📊 Host count: {parsed_data['stats']['hosts']['total']}")
    print(f"📊 Severity breakdown: {parsed_data['stats']['vulnerabilities']['by_severity']}")
    
    # Method B: Using individual classes
    from yapp import NessusParser
    
    parser = NessusParser(NESSUS_FILE)
    parsed_data_direct = parser.parse()
    
    print(f"✅ Direct parsing: {len(parsed_data_direct['vulnerabilities'])} vulnerabilities")
    
    # Example: Working with the data
    critical_vulns = [
        vuln for vuln in parsed_data['vulnerabilities'].values() 
        if vuln['severity'] >= 4
    ]
    print(f"🚨 Found {len(critical_vulns)} critical vulnerabilities")
    
    return parsed_data

def example_3_consolidation_with_file_output():
    """
    Example 3: Parsing + consolidation with file output
    Creates: parsed JSON + consolidated JSON files
    """
    print("\n🔧 Example 3: Parsing + consolidation with file output")
    
    # Method A: Using convenience function
    from yapp import process_nessus_file
    
    results = process_nessus_file(
        nessus_file=NESSUS_FILE,
        consolidate=True,
        output_dir=OUTPUT_DIR
    )
    
    parsed_data = results['parsed']
    consolidated_data = results.get('consolidated')
    
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    
    if consolidated_data:
        metadata = consolidated_data['consolidation_metadata']
        consolidated_vulns = consolidated_data['consolidated_vulnerabilities']
        
        print(f"✅ Consolidated into {len(consolidated_vulns)} categories")
        print(f"📊 Original plugins: {metadata['original_plugins_count']}")
        print(f"📊 Plugins consolidated: {metadata['consolidated_count']}")
        print(f"📁 Files written to: {OUTPUT_DIR}")
    else:
        print("⚠️  No consolidation occurred (no matching rules)")
    
    # Method B: Using individual classes
    from yapp import NessusParser, VulnerabilityConsolidator
    from yapp.utils import write_results_to_files
    
    parser = NessusParser(NESSUS_FILE)
    parsed_data = parser.parse()
    
    consolidator = VulnerabilityConsolidator()  # Uses default rules
    consolidated_data = consolidator.consolidate(parsed_data)
    
    # Manual file writing
    manual_results = {
        'parsed': parsed_data,
        'consolidated': consolidated_data
    }
    write_results_to_files(manual_results, NESSUS_FILE, f"{OUTPUT_DIR}/manual")
    print(f"📁 Manual consolidation files written")
    
    return parsed_data, consolidated_data

def example_4_consolidation_in_memory_only():
    """
    Example 4: Parsing + consolidation in-memory only
    Returns: parsed + consolidated JSON data as variables
    """
    print("\n🧠 Example 4: Parsing + consolidation in-memory only")
    
    # Method A: Using convenience function
    from yapp import process_nessus_file
    
    results = process_nessus_file(
        nessus_file=NESSUS_FILE,
        consolidate=True
        # No output_dir = no files written
    )
    
    parsed_data = results['parsed']
    consolidated_data = results.get('consolidated')
    
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    
    if consolidated_data:
        consolidated_vulns = consolidated_data['consolidated_vulnerabilities']
        print(f"✅ Consolidated into {len(consolidated_vulns)} categories")
        
        # Example: Working with consolidated data
        for rule_name, rule_data in consolidated_vulns.items():
            title = rule_data['title']
            severity = rule_data['severity']
            affected_count = len(rule_data.get('affected_services', {}))
            
            print(f"  🔍 {title} (Severity: {severity}, Affects: {affected_count} services)")
    else:
        print("⚠️  No consolidation occurred")
    
    # Method B: Using individual classes with custom rules
    from yapp import NessusParser, VulnerabilityConsolidator
    
    parser = NessusParser(NESSUS_FILE)
    parsed_data = parser.parse()
    
    # Using custom rules file (if you have one)
    # consolidator = VulnerabilityConsolidator("path/to/custom_rules.json")
    consolidator = VulnerabilityConsolidator()  # Default rules
    consolidated_data = consolidator.consolidate(parsed_data)
    
    print(f"✅ Direct consolidation completed")
    
    return parsed_data, consolidated_data

def example_5_full_pipeline_with_file_output():
    """
    Example 5: Parsing + consolidation + API formatting with file output
    Creates: parsed JSON + consolidated JSON + API JSON files
    """
    print("\n🔧 Example 5: Full pipeline with file output")
    
    # Method A: Using convenience function
    from yapp import process_nessus_file
    
    results = process_nessus_file(
        nessus_file=NESSUS_FILE,
        consolidate=True,
        api_format=True,
        output_dir=OUTPUT_DIR
    )
    
    parsed_data = results['parsed']
    consolidated_data = results.get('consolidated')
    api_data = results.get('api_ready')
    
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    
    if consolidated_data:
        consolidated_vulns = consolidated_data['consolidated_vulnerabilities']
        print(f"✅ Consolidated into {len(consolidated_vulns)} categories")
    
    if api_data:
        print(f"✅ Generated {len(api_data)} API-ready findings")
        print(f"📁 All files written to: {OUTPUT_DIR}")
        
        # Show API data structure
        if api_data:
            first_finding = api_data[0]
            print(f"🔍 API Finding sample: ID={first_finding['finding_id']}, Type={first_finding['type']}")
    else:
        print("⚠️  No API data generated (requires rules with internal_vulnerability_id)")
    
    # Method B: Using individual classes
    from yapp import NessusParser, VulnerabilityConsolidator, APIFormatter
    from yapp.utils import write_results_to_files
    
    # Step-by-step processing
    parser = NessusParser(NESSUS_FILE)
    parsed_data = parser.parse()
    
    consolidator = VulnerabilityConsolidator()
    consolidated_data = consolidator.consolidate(parsed_data)
    
    api_data = None
    if consolidated_data:
        formatter = APIFormatter()
        api_data = formatter.format_for_api(consolidated_data)
    
    # Manual file writing
    manual_results = {
        'parsed': parsed_data,
        'consolidated': consolidated_data,
        'api_ready': api_data
    }
    write_results_to_files(manual_results, NESSUS_FILE, f"{OUTPUT_DIR}/manual_full")
    print(f"📁 Manual full pipeline files written")
    
    return parsed_data, consolidated_data, api_data

def example_6_full_pipeline_in_memory_only():
    """
    Example 6: Parsing + consolidation + API formatting in-memory only
    Returns: parsed + consolidated + API JSON data as variables
    """
    print("\n🧠 Example 6: Full pipeline in-memory only")
    
    # Method A: Using convenience function
    from yapp import process_nessus_file
    
    results = process_nessus_file(
        nessus_file=NESSUS_FILE,
        consolidate=True,
        api_format=True
        # No output_dir = no files written
    )
    
    parsed_data = results['parsed']
    consolidated_data = results.get('consolidated')
    api_data = results.get('api_ready')
    
    print(f"✅ Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
    
    if consolidated_data and api_data:
        print(f"✅ Generated {len(api_data)} API-ready findings")
        
        # Example: Working with API data
        finding_ids = [finding['finding_id'] for finding in api_data]
        unique_finding_ids = list(set(finding_ids))
        
        print(f"📊 Unique finding IDs: {unique_finding_ids}")
        
        # Example: Extract affected entities
        for finding in api_data[:3]:  # Show first 3
            entities_html = finding['affected_entities']
            entity_count = entities_html.count('<br />') + 1 if entities_html else 0
            print(f"  🎯 Finding {finding['finding_id']}: {entity_count} affected entities")
    
    # Method B: Using individual classes with error handling
    from yapp import NessusParser, VulnerabilityConsolidator, APIFormatter
    from yapp import ConsolidationError, FormatterError
    
    try:
        parser = NessusParser(NESSUS_FILE)
        parsed_data = parser.parse()
        print(f"✅ Parsing successful")
        
        consolidator = VulnerabilityConsolidator()
        consolidated_data = consolidator.consolidate(parsed_data)
        print(f"✅ Consolidation successful")
        
        if consolidated_data:
            formatter = APIFormatter()
            api_data = formatter.format_for_api(consolidated_data)
            print(f"✅ API formatting successful")
        else:
            api_data = None
            print("⚠️  No consolidation data for API formatting")
    
    except ConsolidationError as e:
        print(f"❌ Consolidation failed: {e}")
        consolidated_data, api_data = None, None
    except FormatterError as e:
        print(f"❌ API formatting failed: {e}")
        api_data = None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None, None, None
    
    return parsed_data, consolidated_data, api_data

def example_7_entity_limit_functionality():
    """
    Example 7: Using entity limit functionality to control API output size
    Demonstrates entity limiting for findings with too many affected hosts
    """
    print("\n🎯 Example 7: Entity limit functionality")
    
    # Method A: Using convenience function with entity limit
    from yapp import process_nessus_file
    
    print("🔧 Testing without entity limit (unlimited):")
    results_unlimited = process_nessus_file(
        nessus_file=NESSUS_FILE,
        consolidate=True,
        api_format=True
        # No entity_limit = unlimited entities
    )
    
    if results_unlimited.get('api_ready'):
        api_data_unlimited = results_unlimited['api_ready']
        print(f"✅ Generated {len(api_data_unlimited)} findings without limit")
        
        # Show entity counts for each finding
        for finding in api_data_unlimited:
            entities_html = finding['affected_entities']
            if 'replaceMe' in entities_html:
                print(f"  🔗 Finding {finding['finding_id']}: CSV reference (limit applied)")
            else:
                entity_count = entities_html.count('<br />') + 1 if entities_html else 0
                print(f"  📊 Finding {finding['finding_id']}: {entity_count} entities")
    
    print("\n🔧 Testing with entity limit of 5:")
    results_limited = process_nessus_file(
        nessus_file=NESSUS_FILE,
        consolidate=True,
        api_format=True,
        entity_limit=5,  # Limit to 5 entities per finding
        output_dir=f"{OUTPUT_DIR}/limited"
    )
    
    if results_limited.get('api_ready'):
        api_data_limited = results_limited['api_ready']
        print(f"✅ Generated {len(api_data_limited)} findings with entity limit")
        
        # Compare with unlimited version
        csv_references = 0
        for finding in api_data_limited:
            entities_html = finding['affected_entities']
            if 'replaceMe' in entities_html:
                csv_references += 1
                print(f"  🔗 Finding {finding['finding_id']}: CSV reference (>5 entities)")
            else:
                entity_count = entities_html.count('<br />') + 1 if entities_html else 0
                print(f"  📊 Finding {finding['finding_id']}: {entity_count} entities")
        
        print(f"🎯 Findings with CSV reference due to limit: {csv_references}")
    
    # Method B: Using individual classes with different limits
    from yapp import NessusParser, VulnerabilityConsolidator, APIFormatter
    
    print("\n🔧 Testing with individual classes and different entity limits:")
    
    # Parse and consolidate once
    parser = NessusParser(NESSUS_FILE)
    parsed_data = parser.parse()
    
    consolidator = VulnerabilityConsolidator()
    consolidated_data = consolidator.consolidate(parsed_data)
    
    if consolidated_data:
        # Test different entity limits
        limits_to_test = [1, 3, 10, None]  # None = no limit
        
        for limit in limits_to_test:
            print(f"\n  🎛️  Testing entity limit: {limit if limit else 'unlimited'}")
            
            formatter = APIFormatter(entity_limit=limit)
            api_data = formatter.format_for_api(consolidated_data)
            
            if api_data:
                csv_count = sum(1 for f in api_data if 'replaceMe' in f['affected_entities'])
                normal_count = len(api_data) - csv_count
                print(f"    📊 Normal findings: {normal_count}")
                print(f"    🔗 CSV references: {csv_count}")
                
                # Show first finding details
                if api_data:
                    first_finding = api_data[0]
                    entities = first_finding['affected_entities']
                    if 'replaceMe' in entities:
                        print(f"    📄 Sample: Finding {first_finding['finding_id']} → CSV reference")
                    else:
                        entity_count = entities.count('<br />') + 1 if entities else 0
                        print(f"    📄 Sample: Finding {first_finding['finding_id']} → {entity_count} entities")
    
    return results_unlimited, results_limited

def example_8_custom_rules_and_output_names():
    """
    Example 8: Advanced usage with custom rules and output names
    """
    print("\n🔧 Example 8: Advanced usage with custom rules and output names")
    
    from yapp import process_nessus_file
    
    # Using custom rules file (if you have one)
    custom_rules_file = "path/to/my_custom_rules.json"  # Update this path
    
    try:
        results = process_nessus_file(
            nessus_file=NESSUS_FILE,
            consolidate=True,
            api_format=True,
            rules_file=custom_rules_file,  # Custom rules
            entity_limit=10,  # Entity limit for API output
            output_dir=OUTPUT_DIR,
            custom_output_name="advanced_scan_results.json"  # Custom naming
        )
        
        print(f"✅ Advanced processing with custom rules completed")
        print(f"📁 Files created:")
        print(f"  - advanced_scan_results.json")
        print(f"  - advanced_scan_results_Consolidated_Findings.json")
        print(f"  - advanced_scan_results_API_Ready.json")
        
    except FileNotFoundError:
        print(f"⚠️  Custom rules file not found, using default rules")
        
        # Fallback to default rules with entity limit
        results = process_nessus_file(
            nessus_file=NESSUS_FILE,
            consolidate=True,
            api_format=True,
            entity_limit=10,  # Apply entity limit
            output_dir=OUTPUT_DIR,
            custom_output_name="advanced_scan_results.json"
        )
        
        print(f"✅ Advanced processing with default rules and entity limit completed")
    
    return results

def example_9_error_handling_and_validation():
    """
    Example 9: Error handling and validation for entity limits
    """
    print("\n🛡️  Example 9: Error handling and validation")
    
    from yapp import APIFormatter, FormatterError
    
    # Test invalid entity limits
    print("🔧 Testing invalid entity limit values:")
    
    invalid_limits = [0, -1, -10]
    for limit in invalid_limits:
        try:
            formatter = APIFormatter(entity_limit=limit)
            print(f"  ❌ Limit {limit}: Should have failed but didn't")
        except FormatterError as e:
            print(f"  ✅ Limit {limit}: Correctly rejected - {e}")
    
    # Test valid entity limits
    print("\n🔧 Testing valid entity limit values:")
    
    valid_limits = [1, 5, 10, 100, None]
    for limit in valid_limits:
        try:
            formatter = APIFormatter(entity_limit=limit)
            limit_str = str(limit) if limit is not None else "unlimited"
            print(f"  ✅ Limit {limit_str}: Valid")
        except FormatterError as e:
            print(f"  ❌ Limit {limit}: Unexpected error - {e}")
    
    # Test with actual processing
    print("\n🔧 Testing entity limit in full processing with error handling:")
    
    from yapp import process_nessus_file, ConsolidationError, FormatterError
    
    try:
        results = process_nessus_file(
            nessus_file=NESSUS_FILE,
            consolidate=True,
            api_format=True,
            entity_limit=3
        )
        
        print("✅ Processing with entity limit successful")
        
        if results.get('api_ready'):
            api_data = results['api_ready']
            csv_references = sum(1 for f in api_data if 'replaceMe' in f['affected_entities'])
            print(f"📊 Generated {len(api_data)} findings")
            print(f"🔗 CSV references applied: {csv_references}")
        
    except FormatterError as e:
        print(f"❌ Formatter error: {e}")
    except ConsolidationError as e:
        print(f"❌ Consolidation error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def main():
    """Run all examples"""
    print("🚀 YAPP Programmatic Usage Examples with Entity Limit\n")
    
    # Create output directory
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Run examples
    examples = [
        ("Basic parsing with file output", example_1_parsing_with_file_output),
        ("Basic parsing in-memory only", example_2_parsing_in_memory_only),
        ("Consolidation with file output", example_3_consolidation_with_file_output),
        ("Consolidation in-memory only", example_4_consolidation_in_memory_only),
        ("Full pipeline with file output", example_5_full_pipeline_with_file_output),
        ("Full pipeline in-memory only", example_6_full_pipeline_in_memory_only),
        ("Entity limit functionality", example_7_entity_limit_functionality),
        ("Error handling and validation", example_9_error_handling_and_validation)
        # ("Advanced usage", example_8_custom_rules_and_output_names),
    ]
    
    results = {}
    
    for name, example_func in examples:
        try:
            print(f"\n{'='*60}")
            result = example_func()
            results[name] = result
            print(f"✅ {name} completed successfully")
        except Exception as e:
            print(f"❌ {name} failed: {e}")
            results[name] = None
    
    # Summary
    print(f"\n{'='*60}")
    print("📋 EXAMPLES SUMMARY")
    print(f"{'='*60}")
    
    for name, result in results.items():
        status = "✅ SUCCESS" if result is not None else "❌ FAILED"
        print(f"{status}: {name}")
    
    # Show output files created
    output_path = Path(OUTPUT_DIR)
    if output_path.exists():
        files = list(output_path.glob("**/*.json"))  # Include subdirectories
        print(f"\n📁 Files created in {OUTPUT_DIR}:")
        for file in sorted(files):
            print(f"  - {file.relative_to(output_path)}")

if __name__ == "__main__":
    main()
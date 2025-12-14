"""
EKS AI-Enhanced Architecture Design Wizard - Integration Module
Wrapper module for integration with AWS WAF Scanner application

This module wraps all EKS wizard functionality into a single render function
that can be called from the main streamlit_app.py as a new tab.

Author: Infosys Cloud Architecture Team
Version: 2.0.0
"""

import streamlit as st
import json
import yaml
import io
import zipfile
from datetime import datetime
from typing import Dict, List, Any, Optional

# ============================================================================
# MODULE IMPORTS WITH ERROR HANDLING
# ============================================================================

EKS_WIZARD_STATUS = {}

# Core AI Requirements Engine
try:
    from eks_ai_architecture_wizard import (
        EKSAIRequirementsEngine,
        EKSWorkloadAnalyzer,
        EKSClusterConfig,
        WorkloadType,
        ClusterTopology,
        AvailabilityTier,
        ComplianceFramework,
        SecurityLevel
    )
    EKS_WIZARD_STATUS['core'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['core'] = False
    print(f"EKS Core module not available: {e}")

# Security Module
try:
    from eks_security_module_v2 import (
        EKSSecurityAnalyzer,
        COMPLIANCE_CONTROLS,
        CIS_BENCHMARK_CONTROLS
    )
    EKS_WIZARD_STATUS['security'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['security'] = False
    COMPLIANCE_CONTROLS = {}
    CIS_BENCHMARK_CONTROLS = {}

# GitOps Module
try:
    from eks_gitops_generator import (
        GitOpsConfigurationGenerator,
        GitOpsConfiguration,
        GitOpsToolType,
        REPOSITORY_STRUCTURES
    )
    EKS_WIZARD_STATUS['gitops'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['gitops'] = False
    REPOSITORY_STRUCTURES = {}

# FinOps Module
try:
    from eks_finops_module import (
        EKSCostCalculator,
        KarpenterConfigGenerator,
        KubecostIntegration,
        EC2_PRICING
    )
    EKS_WIZARD_STATUS['finops'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['finops'] = False
    EC2_PRICING = {}

# Observability Module
try:
    from eks_observability_module import (
        PrometheusConfigGenerator,
        LoggingConfigGenerator,
        TracingConfigGenerator,
        GrafanaDashboardGenerator
    )
    EKS_WIZARD_STATUS['observability'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['observability'] = False

# IaC Export Module
try:
    from eks_iac_export import (
        TerraformGenerator,
        CloudFormationGenerator
    )
    EKS_WIZARD_STATUS['iac'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['iac'] = False

# Documentation Module
try:
    from eks_documentation_generator import (
        ADRGenerator,
        RunbookGenerator,
        ArchitectureDocGenerator
    )
    EKS_WIZARD_STATUS['docs'] = True
except ImportError as e:
    EKS_WIZARD_STATUS['docs'] = False

# ============================================================================
# INFOSYS STYLING
# ============================================================================

INFOSYS_BLUE = "#007CC3"

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

def init_eks_wizard_state():
    """Initialize EKS wizard session state"""
    if 'eks_cluster_config' not in st.session_state:
        st.session_state.eks_cluster_config = None
    if 'eks_parsed_requirements' not in st.session_state:
        st.session_state.eks_parsed_requirements = None
    if 'eks_security_assessment' not in st.session_state:
        st.session_state.eks_security_assessment = None
    if 'eks_cost_estimate' not in st.session_state:
        st.session_state.eks_cost_estimate = None
    if 'eks_generated_configs' not in st.session_state:
        st.session_state.eks_generated_configs = {}

# ============================================================================
# MAIN RENDER FUNCTION
# ============================================================================

class EKSArchitectureWizardModule:
    """EKS Architecture Wizard Module for integration with WAF Scanner"""
    
    @staticmethod
    def render():
        """Main render function - call this from streamlit_app.py"""
        
        init_eks_wizard_state()
        
        # Header
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, {INFOSYS_BLUE} 0%, #005a8c 100%); 
                    padding: 15px 20px; border-radius: 10px; color: white; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h2 style="margin: 0; color: white;">🚀 EKS AI Architecture Design Wizard</h2>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">Enterprise Kubernetes architecture with AI-powered recommendations</p>
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 1.2rem; font-weight: bold;">v2.0</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Module status
        loaded_count = sum(1 for v in EKS_WIZARD_STATUS.values() if v)
        total_count = len(EKS_WIZARD_STATUS)
        
        if loaded_count < total_count:
            with st.expander(f"⚠️ Module Status ({loaded_count}/{total_count} loaded)", expanded=False):
                for module, status in EKS_WIZARD_STATUS.items():
                    if status:
                        st.success(f"✅ {module.title()}")
                    else:
                        st.error(f"❌ {module.title()}")
        
        # Main tabs
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "🎯 Requirements",
            "🏗️ Architecture",
            "🔒 Security",
            "💰 FinOps",
            "📦 IaC Export",
            "📋 Summary"
        ])
        
        with tab1:
            EKSArchitectureWizardModule._render_requirements_tab()
        
        with tab2:
            EKSArchitectureWizardModule._render_architecture_tab()
        
        with tab3:
            EKSArchitectureWizardModule._render_security_tab()
        
        with tab4:
            EKSArchitectureWizardModule._render_finops_tab()
        
        with tab5:
            EKSArchitectureWizardModule._render_iac_tab()
        
        with tab6:
            EKSArchitectureWizardModule._render_summary_tab()
    
    @staticmethod
    def _render_requirements_tab():
        """Render requirements gathering tab"""
        
        st.markdown("### 🎯 Define Your EKS Requirements")
        
        input_method = st.radio(
            "Input Method",
            ["💬 Natural Language (AI)", "📝 Form Input"],
            horizontal=True
        )
        
        if input_method == "💬 Natural Language (AI)":
            st.markdown("""
            **Describe your EKS architecture needs in plain English.** 
            Our AI will parse your requirements and generate optimal configurations.
            """)
            
            with st.expander("💡 Example Prompts"):
                st.markdown("""
                - *"I need to migrate 50 Java microservices to EKS. They handle 10,000 requests/second with 99.99% uptime. We're PCI-DSS compliant."*
                - *"Set up a development EKS cluster for our ML team with GPU support and SageMaker integration."*
                - *"Production cluster for e-commerce, 20 services, peak traffic during Black Friday, HIPAA compliant."*
                """)
            
            user_requirements = st.text_area(
                "Enter your requirements:",
                height=120,
                placeholder="Describe your EKS architecture requirements here..."
            )
            
            if st.button("🤖 Analyze Requirements", type="primary"):
                if user_requirements and EKS_WIZARD_STATUS.get('core'):
                    with st.spinner("AI is analyzing your requirements..."):
                        try:
                            engine = EKSAIRequirementsEngine()
                            parsed = engine.parse_natural_language_requirements(user_requirements)
                            st.session_state.eks_parsed_requirements = parsed
                            
                            recommendations = engine.generate_architecture_recommendation(parsed)
                            
                            st.session_state.eks_cluster_config = {
                                "cluster_name": parsed.get("cluster_name", "eks-cluster"),
                                "kubernetes_version": "1.29",
                                "region": "us-east-1",
                                "environment": "production",
                                "node_groups": recommendations.get("node_groups", []),
                                "security": recommendations.get("security_config", {}),
                                "observability": recommendations.get("observability_config", {}),
                                "network": recommendations.get("networking_config", {}),
                                "cost": recommendations.get("cost_optimization", {})
                            }
                            
                            st.success("✅ Requirements analyzed successfully!")
                        except Exception as e:
                            st.error(f"Error analyzing requirements: {str(e)}")
                elif not EKS_WIZARD_STATUS.get('core'):
                    st.error("Core module not loaded. Cannot analyze requirements.")
                else:
                    st.warning("Please enter your requirements.")
            
            # Display parsed requirements
            if st.session_state.eks_parsed_requirements:
                st.markdown("---")
                st.markdown("### 📋 Parsed Requirements")
                parsed = st.session_state.eks_parsed_requirements
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Workloads", parsed.get("workload_summary", {}).get("count", "N/A"))
                with col2:
                    st.metric("Availability", parsed.get("performance", {}).get("availability_target", "99.9%"))
                with col3:
                    budget = parsed.get("budget", {}).get("monthly_usd", 0)
                    st.metric("Budget", f"${budget:,.0f}/mo")
                
                if parsed.get("compliance"):
                    st.markdown("**Compliance Requirements:**")
                    st.write(", ".join([c.upper().replace("_", "-") for c in parsed.get("compliance", [])]))
        
        else:
            # Form-based input
            EKSArchitectureWizardModule._render_form_input()
    
    @staticmethod
    def _render_form_input():
        """Render form-based input"""
        
        col1, col2 = st.columns(2)
        
        with col1:
            cluster_name = st.text_input("Cluster Name", value="eks-production")
            k8s_version = st.selectbox("Kubernetes Version", ["1.29", "1.28", "1.27"])
            region = st.selectbox("AWS Region", [
                "us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1"
            ])
        
        with col2:
            environment = st.selectbox("Environment", ["production", "staging", "development"])
            budget = st.number_input("Monthly Budget (USD)", min_value=0, value=10000)
        
        st.markdown("#### Compliance Requirements")
        comp_cols = st.columns(4)
        pci = comp_cols[0].checkbox("PCI-DSS")
        hipaa = comp_cols[1].checkbox("HIPAA")
        soc2 = comp_cols[2].checkbox("SOC 2")
        iso = comp_cols[3].checkbox("ISO 27001")
        
        if st.button("Generate Configuration", type="primary"):
            compliance = []
            if pci: compliance.append("pci_dss")
            if hipaa: compliance.append("hipaa")
            if soc2: compliance.append("soc2")
            if iso: compliance.append("iso_27001")
            
            st.session_state.eks_cluster_config = {
                "cluster_name": cluster_name,
                "kubernetes_version": k8s_version,
                "region": region,
                "environment": environment,
                "budget_monthly_usd": budget,
                "compliance": compliance,
                "node_groups": [
                    {
                        "name": "system",
                        "instance_types": ["m6i.large"],
                        "capacity_type": "ON_DEMAND",
                        "min_size": 2,
                        "max_size": 4,
                        "desired_size": 2
                    },
                    {
                        "name": "application",
                        "instance_types": ["m6i.xlarge"],
                        "capacity_type": "SPOT" if budget < 20000 else "ON_DEMAND",
                        "min_size": 2,
                        "max_size": 20,
                        "desired_size": 3
                    }
                ],
                "security": {
                    "private_endpoint": True,
                    "public_endpoint": environment == "development",
                    "enable_secrets_encryption": True,
                    "enable_network_policies": True,
                    "enable_audit_logging": True
                }
            }
            st.success("✅ Configuration created!")
    
    @staticmethod
    def _render_architecture_tab():
        """Render architecture designer tab"""
        
        st.markdown("### 🏗️ Architecture Designer")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first in the Requirements tab.")
            return
        
        config = st.session_state.eks_cluster_config
        
        # Cluster topology
        st.markdown("#### Cluster Topology")
        topology = st.selectbox(
            "Select Topology Pattern",
            ["Single Cluster", "Hub-Spoke", "Federated", "Cluster-per-Team"]
        )
        
        topology_info = {
            "Single Cluster": "Best for: Small-medium teams, dev/test. Simple management, lower cost.",
            "Hub-Spoke": "Best for: Enterprise with multiple teams. Centralized management, good isolation.",
            "Federated": "Best for: Global deployments, mission critical. Multi-region, DR capable.",
            "Cluster-per-Team": "Best for: Strong isolation needs. Team autonomy, clear boundaries."
        }
        st.info(topology_info.get(topology, ""))
        
        # Node Groups
        st.markdown("#### Node Groups")
        node_groups = config.get("node_groups", [])
        
        for i, ng in enumerate(node_groups):
            with st.expander(f"🖥️ {ng.get('name', f'group-{i}')}", expanded=i==0):
                col1, col2, col3 = st.columns(3)
                with col1:
                    ng['instance_types'] = st.multiselect(
                        f"Instance Types##{i}",
                        options=["m6i.large", "m6i.xlarge", "m6i.2xlarge", "c6i.xlarge", "r6i.xlarge", "g5.xlarge"],
                        default=ng.get('instance_types', ['m6i.xlarge'])
                    )
                with col2:
                    ng['capacity_type'] = st.selectbox(
                        f"Capacity##{i}",
                        ["ON_DEMAND", "SPOT"],
                        index=0 if ng.get('capacity_type') == 'ON_DEMAND' else 1
                    )
                with col3:
                    ng['desired_size'] = st.number_input(f"Nodes##{i}", value=ng.get('desired_size', 2), min_value=1)
        
        # Add-ons
        st.markdown("#### EKS Add-ons")
        addon_cols = st.columns(3)
        with addon_cols[0]:
            st.checkbox("VPC CNI (Required)", value=True, disabled=True)
            st.checkbox("EBS CSI Driver", value=True, key="addon_ebs")
        with addon_cols[1]:
            st.checkbox("CoreDNS (Required)", value=True, disabled=True)
            st.checkbox("AWS LB Controller", value=True, key="addon_alb")
        with addon_cols[2]:
            st.checkbox("kube-proxy (Required)", value=True, disabled=True)
            st.checkbox("Karpenter", value=True, key="addon_karpenter")
    
    @staticmethod
    def _render_security_tab():
        """Render security assessment tab"""
        
        st.markdown("### 🔒 Security & Compliance")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first.")
            return
        
        config = st.session_state.eks_cluster_config
        
        if st.button("🔍 Run Security Assessment", type="primary"):
            if EKS_WIZARD_STATUS.get('security'):
                with st.spinner("Analyzing security configuration..."):
                    try:
                        analyzer = EKSSecurityAnalyzer()
                        assessment = analyzer.assess_security_posture(config)
                        st.session_state.eks_security_assessment = assessment
                        st.success("Assessment complete!")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.error("Security module not loaded.")
        
        if st.session_state.eks_security_assessment:
            assessment = st.session_state.eks_security_assessment
            
            score = assessment.get('score', 0)
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                color = "green" if score >= 80 else "orange" if score >= 60 else "red"
                st.markdown(f"""
                <div style="text-align: center; padding: 15px; background: {color}; border-radius: 8px; color: white;">
                    <div style="font-size: 2rem; font-weight: bold;">{score}</div>
                    <div>Security Score</div>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                st.metric("Critical", assessment.get('findings_summary', {}).get('critical', 0))
            with col3:
                st.metric("High", assessment.get('findings_summary', {}).get('high', 0))
            with col4:
                st.metric("Medium", assessment.get('findings_summary', {}).get('medium', 0))
            
            # Findings
            if assessment.get('findings'):
                st.markdown("#### Findings")
                for finding in assessment.get('findings', [])[:5]:
                    severity = finding.get('severity', 'info')
                    icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                    with st.expander(f"{icon} {finding.get('title', 'Finding')}"):
                        st.markdown(f"**Category:** {finding.get('category', 'N/A')}")
                        st.markdown(f"**Remediation:** {finding.get('remediation', 'N/A')}")
    
    @staticmethod
    def _render_finops_tab():
        """Render FinOps cost optimization tab"""
        
        st.markdown("### 💰 FinOps - Cost Optimization")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first.")
            return
        
        config = st.session_state.eks_cluster_config
        
        if st.button("💵 Calculate Costs", type="primary"):
            if EKS_WIZARD_STATUS.get('finops'):
                with st.spinner("Calculating costs..."):
                    try:
                        calculator = EKSCostCalculator(region=config.get("region", "us-east-1"))
                        estimate = calculator.calculate_cluster_cost(config)
                        st.session_state.eks_cost_estimate = estimate
                        st.success("Cost calculation complete!")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.error("FinOps module not loaded.")
        
        if st.session_state.eks_cost_estimate:
            estimate = st.session_state.eks_cost_estimate
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Monthly Cost", f"${estimate.monthly_total:,.0f}")
            with col2:
                st.metric("Annual Cost", f"${estimate.annual_total:,.0f}")
            with col3:
                st.metric("Potential Savings", f"${estimate.potential_monthly_savings:,.0f}/mo")
            
            # Recommendations
            if estimate.cost_optimization_recommendations:
                st.markdown("#### 💡 Optimization Recommendations")
                for rec in estimate.cost_optimization_recommendations[:3]:
                    with st.expander(f"💡 {rec.get('title', 'Recommendation')} - Save ${rec.get('potential_savings', 0):,.0f}/mo"):
                        st.markdown(f"**Description:** {rec.get('description', '')}")
                        st.markdown(f"**Effort:** {rec.get('effort', 'N/A')} | **Risk:** {rec.get('risk', 'N/A')}")
    
    @staticmethod
    def _render_iac_tab():
        """Render Infrastructure as Code export tab"""
        
        st.markdown("### 📦 Infrastructure as Code Export")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Please define requirements first.")
            return
        
        config = st.session_state.eks_cluster_config
        
        iac_type = st.radio("Select IaC Tool", ["Terraform", "CloudFormation"], horizontal=True)
        
        if st.button(f"Generate {iac_type}", type="primary"):
            if EKS_WIZARD_STATUS.get('iac'):
                with st.spinner(f"Generating {iac_type} configuration..."):
                    try:
                        if iac_type == "Terraform":
                            generator = TerraformGenerator()
                            configs = generator.generate_terraform(config)
                        else:
                            generator = CloudFormationGenerator()
                            configs = generator.generate_cloudformation(config)
                        
                        st.session_state.eks_generated_configs[iac_type.lower()] = configs
                        st.success(f"✅ {iac_type} configuration generated!")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
            else:
                st.error("IaC module not loaded.")
        
        # Display generated configs
        key = iac_type.lower()
        if st.session_state.eks_generated_configs.get(key):
            configs = st.session_state.eks_generated_configs[key]
            
            for filename, content in list(configs.items())[:5]:
                with st.expander(f"📄 {filename}"):
                    lang = "hcl" if filename.endswith('.tf') else "yaml"
                    st.code(content[:3000] + ("..." if len(content) > 3000 else ""), language=lang)
            
            # Download button
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                for filename, content in configs.items():
                    zf.writestr(f"{iac_type.lower()}/{filename}", content)
            
            st.download_button(
                label=f"📥 Download {iac_type} Package",
                data=zip_buffer.getvalue(),
                file_name=f"{config.get('cluster_name', 'eks')}-{iac_type.lower()}.zip",
                mime="application/zip"
            )
    
    @staticmethod
    def _render_summary_tab():
        """Render summary and export tab"""
        
        st.markdown("### 📋 Architecture Summary")
        
        if not st.session_state.eks_cluster_config:
            st.info("👆 Complete the wizard to see summary.")
            return
        
        config = st.session_state.eks_cluster_config
        
        # Overview
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Cluster", config.get("cluster_name", "N/A"))
        with col2:
            st.metric("K8s Version", config.get("kubernetes_version", "1.29"))
        with col3:
            st.metric("Node Groups", len(config.get("node_groups", [])))
        with col4:
            st.metric("Region", config.get("region", "us-east-1"))
        
        # Security Summary
        if st.session_state.eks_security_assessment:
            st.markdown("---")
            assessment = st.session_state.eks_security_assessment
            st.metric("Security Score", f"{assessment.get('score', 0)}/100")
        
        # Cost Summary
        if st.session_state.eks_cost_estimate:
            st.markdown("---")
            estimate = st.session_state.eks_cost_estimate
            st.metric("Estimated Monthly Cost", f"${estimate.monthly_total:,.0f}")
        
        # Export options
        st.markdown("---")
        st.markdown("### 📥 Export Configuration")
        
        col1, col2 = st.columns(2)
        with col1:
            config_json = json.dumps(config, indent=2, default=str)
            st.download_button(
                "📄 Download Config (JSON)",
                config_json,
                f"{config.get('cluster_name', 'eks')}-config.json",
                "application/json"
            )
        with col2:
            config_yaml = yaml.dump(config, default_flow_style=False)
            st.download_button(
                "📄 Download Config (YAML)",
                config_yaml,
                f"{config.get('cluster_name', 'eks')}-config.yaml",
                "text/yaml"
            )


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def render_eks_architecture_wizard():
    """Convenience function to render the EKS Architecture Wizard"""
    EKSArchitectureWizardModule.render()

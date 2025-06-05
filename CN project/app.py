# Import statements first
import streamlit as st
import pandas as pd
import numpy as np
import pickle
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Set page config FIRST - before any other st commands
st.set_page_config(
    page_title="Network Intrusion Detection",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Set paths and constants
MODEL_PATH = ("Network_Intrusion_Detection.pkl")
DATA_PATH = ("Network_Intrusion_Detection_Dataset.csv")
FEATURES = [
    'Port Number', 'Received Packets', 'Received Bytes', 'Sent Bytes', 
    'Sent Packets', 'Port alive Duration (S)', 'Packets Rx Dropped',
    'Packets Tx Dropped', 'Packets Rx Errors', 'Packets Tx Errors',
    'Delta Received Packets', 'Delta Received Bytes', 'Delta Sent Bytes',
    'Delta Sent Packets', 'Delta Port alive Duration (S)',
    'Delta Packets Rx Dropped', ' Delta Packets Tx Dropped',
    'Delta Packets Rx Errors', 'Delta Packets Tx Errors',
    'Connection Point', 'Total Load/Rate', 'Total Load/Latest',
    'Unknown Load/Rate', 'Unknown Load/Latest', 'Latest bytes counter',
    'is_valid', 'Table ID', 'Active Flow Entries', 'Packets Looked Up',
    'Packets Matched', 'Max Size'
]

# --- THEME: Enhanced dark theme from paste-2.txt ---
st.markdown("""
    <style>
    /* Main app background */
    .stApp {
        background-color: #121212;
        color: #ffffff;
    }
    
    /* Headers with subtle accent */
    h1, h2, h3, h4, h5, h6 {
        color: #ffffff !important;
        border-bottom: 1px solid #444444;
        padding-bottom: 8px;
    }
    
    /* Sidebar styling */
    .css-1d391kg, .css-1wrcr25 {
        background-color: #1a1a1a !important;
        border-right: 1px solid #333333 !important;
    }
    
    /* Cards with subtle glow */
    .css-1y4p8pa, .css-1xarl3l {
        background-color: #1e1e1e;
        border: 1px solid #333333;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    
    /* Input fields */
    .stNumberInput > div > div > input {
        color: #ffffff !important;
        background-color: #2a2a2a !important;
        border: 1px solid #444444 !important;
    }
    
    /* Buttons with hover effect */
    .stButton > button {
        background-color: #2a2a2a;
        color: #ffffff;
        border: 1px solid #555555;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        background-color: #3a3a3a;
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    
    /* Tabs with active indicator */
    .stTabs [data-baseweb="tab"] {
        color: #aaaaaa !important;
        padding: 8px 16px !important;
        transition: all 0.3s ease;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff !important;
        font-weight: bold;
        border-bottom: 2px solid #4a8fe7 !important;
    }
    
    /* Alerts with better contrast */
    .stAlert {
        border-left: 4px solid !important;
    }
    .stSuccess {
        border-left-color: #4CAF50 !important;
        background-color: #1B5E20 !important;
    }
    .stError {
        border-left-color: #F44336 !important;
        background-color: #B71C1C !important;
    }
    .stInfo {
        border-left-color: #2196F3 !important;
        background-color: #0D47A1 !important;
    }
    
    /* Plot containers */
    .js-plotly-plot, .plotly, .plotly-container {
        background-color: #1e1e1e !important;
        border-radius: 8px;
        border: 1px solid #333333;
    }
    
    /* Footer styling */
    footer {
        color: #666666 !important;
        font-size: 0.9em;
        text-align: center;
        padding: 16px 0;
    }
    </style>
""", unsafe_allow_html=True)
# --- END THEME ---

# Initialize session state
if 'prediction' not in st.session_state:
    st.session_state.prediction = None

# Load functions
@st.cache_resource
def load_model():
    try:
        return pickle.load(open(MODEL_PATH, "rb"))
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

@st.cache_data
def load_data():
    try:
        return pd.read_csv(DATA_PATH)
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return None

# Initialize
model = load_model()
df = load_data()

if model is None or df is None:
    st.error("Failed to load model or data. Please check the file paths.")
    st.stop()

# Attack types mapping
attack_types = {
    0: "🟢 LEGITIMATE NETWORK TRAFFIC",
    1: "🔴 DDoS ATTACK DETECTED",
    2: "🔴 PROTOCOL EXPLOITATION DETECTED",
    3: "🔴 RECONNAISSANCE DETECTED",
    4: "🔴 TRAFFIC MANIPULATION DETECTED",
    5: "🔴 BUFFER OVERFLOW DETECTED"
}

# Enhanced title with description
st.title("🛡️ Network Intrusion Detection System")
st.markdown("""
    <div style='background-color: #111111; padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #00ff00; box-shadow: 0 0 15px #00ff00;'>
        <p style='font-size: 1.2em; color: #00ff00; font-family: "Courier New", monospace;'>
            Welcome to our advanced Network Intrusion Detection System. This AI-powered platform helps identify and classify
            various types of network attacks in real-time, ensuring your network's security.
        </p>
    </div>
""", unsafe_allow_html=True)

# Enhanced sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/network-protection.png", width=100)
    st.markdown("## Navigation")
    page = st.selectbox("Choose a page", ["Attack Detection", "Advanced Analytics", "Detection Result"])
    
    st.markdown("---")
    st.markdown("### System Statistics")
    col1, col2 = st.columns(2)
    col1.metric("Total Records", len(df))
    col2.metric("Attack Types", len(attack_types))

if page == "Attack Detection":
    st.header("🔍 Network Attack Detection")
    
    # Enhanced input form
    with st.expander("ℹ️ How to use the detection form", expanded=False):
        st.markdown("""
            1. Input your network traffic parameters in the fields below
            2. Use the default values as reference points
            3. Click 'Detect Attack' to analyze the traffic
            4. View results in the 'Detection Result' page
        """)
    
    # Create columns for better layout
    col1, col2, col3 = st.columns(3)
    
    input_data = {}
    for i, feature in enumerate(FEATURES):
        with col1 if i % 3 == 0 else col2 if i % 3 == 1 else col3:
            input_data[feature] = st.number_input(
                f"{feature}",
                value=float(df[feature].mean()),
                help=f"Average value: {df[feature].mean():.2f}"
            )
    
    # Enhanced detection button
    if st.button("🔍 Detect Attack", use_container_width=True):
        with st.spinner('Analyzing network traffic...'):
            input_df = pd.DataFrame([input_data])[FEATURES]
            try:
                st.session_state.prediction = model.predict(input_df)[0]
                st.success("Detection complete! View result in the 'Detection Result' page.")
            except Exception as e:
                st.error(f"Error in attack detection: {e}")

elif page == "Advanced Analytics":
    st.header("📊 Advanced Network Analytics")
    
    # Create tabs for different visualizations
    tabs = st.tabs([
        "Attack Distribution", 
        "Correlation Analysis",
        "Traffic Patterns",
        "Feature Analysis",
        "Network Metrics",
        "Time Series Analysis"
    ])
    
    with tabs[0]:
        st.subheader("📊 Distribution of Attack Types")
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Enhanced pie chart with cyberpunk colors
            labels = list(attack_types.values())
            values = df['Label'].value_counts().sort_index()
            
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=.3,
                marker_colors=['#00ff00', '#ff0000', '#ff3300', '#ffff00', '#ff00ff', '#00ffff']
            )])
            
            # Update layout with cyberpunk theme
            fig.update_layout(
                title="Attack Type Distribution",
                paper_bgcolor='#111111',
                plot_bgcolor='#111111',
                font=dict(color='#00ff00'),
                title_font_color='#00ff00'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("""
                ### Key Insights
                - Shows the proportion of different attack types
                - Helps identify most common threats
                - Enables better resource allocation
            """)
    
    with tabs[1]:
        st.subheader("🔗 Feature Correlation Analysis")
        
        # Enhanced correlation heatmap
        num_features = st.slider("Number of features to show", 5, 15, 10)
        correlations = df.corr()['Label'].abs().sort_values(ascending=False)
        top_features = correlations.head(num_features).index
        
        fig = px.imshow(
            df[top_features].corr(),
            color_continuous_scale='RdBu_r',
            title=f"Top {num_features} Most Correlated Features"
        )
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("""
            ### Understanding Correlations
            - Strong positive correlations appear in red
            - Strong negative correlations appear in blue
            - Features with high correlation with 'Label' are important for detection
        """)
    
    with tabs[2]:
        st.subheader("📈 Traffic Patterns")
        
        # Scatter plot matrix
        selected_features = st.multiselect(
            "Select features for analysis",
            FEATURES,
            default=FEATURES[:3]
        )
        
        if selected_features:
            fig = px.scatter_matrix(
                df,
                dimensions=selected_features,
                color='Label',
                title="Network Traffic Patterns Analysis"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[3]:
        st.subheader("📊 Feature Distribution Analysis")
        
        # Enhanced box plots and histograms
        selected_feature = st.selectbox("Select feature to analyze", FEATURES)
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.box(
                df,
                x='Label',
                y=selected_feature,
                color='Label',
                title=f"Distribution of {selected_feature} by Attack Type"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.histogram(
                df,
                x=selected_feature,
                color='Label',
                title=f"Histogram of {selected_feature}"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tabs[4]:
        st.subheader("📊 Network Metrics")
        
        # Radar chart of average metrics by attack type
        metrics = ['Received Packets', 'Sent Packets', 'Total Load/Rate']
        
        fig = go.Figure()
        
        for label in df['Label'].unique():
            values = df[df['Label'] == label][metrics].mean().values.tolist()
            values.append(values[0])  # Close the polygon
            
            fig.add_trace(go.Scatterpolar(
                r=values,
                theta=metrics + [metrics[0]],
                name=attack_types[label]
            ))
            
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
            title="Average Network Metrics by Attack Type"
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with tabs[5]:
        st.subheader("📈 Time Series Analysis")
        
        # Line chart of network metrics over time
        metric = st.selectbox("Select metric for time analysis", FEATURES)
        
        fig = px.line(
            df,
            y=metric,
            color='Label',
            title=f"{metric} Over Time"
        )
        
        st.plotly_chart(fig, use_container_width=True)

else:  # Detection Result page
    st.header("🎯 Detection Result")
    
    if st.session_state.prediction is not None:
        # Enhanced result display with cyberpunk theme
        result = attack_types[st.session_state.prediction]
        is_legitimate = st.session_state.prediction == 0
        
        st.markdown(
            f"""
            <div style='text-align: center; padding: 50px; 
                        background-color: {'#003300' if is_legitimate else '#330000'}; 
                        border: 2px solid {'#00ff00' if is_legitimate else '#ff0000'}; 
                        border-radius: 10px; margin: 20px 0; color: {'#00ff00' if is_legitimate else '#ff0000'};
                        box-shadow: 0 0 20px {'#00ff00' if is_legitimate else '#ff0000'};'>
                <h1 style='font-size: 2.5em; font-family: "Courier New", monospace;'>{result}</h1>
                <p style='font-size: 1.2em; margin-top: 20px; font-family: "Courier New", monospace;'>
                    {'Your network traffic appears normal.' if is_legitimate else 'Potential security threat detected!'}
                </p>
            </div>
            """, 
            unsafe_allow_html=True
        )
        
        # Add recommendations with cyberpunk styling
        if not is_legitimate:
            st.markdown("""
                <div style='background-color: #111111; padding: 20px; border-radius: 10px; border: 1px solid #ff0000; box-shadow: 0 0 10px #ff0000;'>
                    <h3 style='color: #ff0000; text-shadow: 0 0 5px #ff0000;'>🚨 Recommended Actions:</h3>
                    <ol style='color: #ff3333; font-family: "Courier New", monospace;'>
                        <li>Isolate affected systems</li>
                        <li>Review security logs</li>
                        <li>Update firewall rules</li>
                        <li>Contact security team</li>
                    </ol>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No detection results yet. Please go to the 'Attack Detection' page to analyze network traffic.")

# Enhanced footer with dark theme
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666666; font-size: 0.9em;'>
        <p>Network Intrusion Detection System • Powered by Advanced Machine Learning • Built with Streamlit</p>
        <p style='font-size: 0.8em; margin-top: 10px;'>© 2024 Security Operations Center</p>
    </div>
""", unsafe_allow_html=True)

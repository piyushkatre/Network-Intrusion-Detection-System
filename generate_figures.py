"""
Generate figures for the B-NIDS research paper:
1. Confusion Matrix for XGBoost
2. Latency comparison bar chart
3. Model comparison bar chart
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from sklearn.metrics import confusion_matrix, classification_report
import joblib
import json


def generate_confusion_matrix():
    """Generate confusion matrix for XGBoost model."""
    print("Loading data and model...")
    data_dir = 'data'
    model_dir = 'models'

    X_test = np.load(f'{data_dir}/X_test.npy')
    y_test = np.load(f'{data_dir}/y_test.npy')
    model = joblib.load(f'{model_dir}/best_model.pkl')
    label_encoder = joblib.load(f'{data_dir}/label_encoder.pkl')
    scaler = joblib.load(f'{data_dir}/scaler.pkl')
    feature_columns = np.load(f'{data_dir}/feature_columns.npy', allow_pickle=True)

    print(f"Test set size: {X_test.shape}")
    print(f"Classes: {label_encoder.classes_}")

    # Predict
    y_pred = model.predict(X_test)

    # Get class labels
    class_labels = label_encoder.classes_

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    # Classification report
    report = classification_report(y_test, y_pred, target_names=class_labels)
    print("\nClassification Report:")
    print(report)

    # --- Plot Confusion Matrix ---
    fig, ax = plt.subplots(figsize=(10, 8))

    # Normalize for better visualization
    cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

    im = ax.imshow(cm_normalized, interpolation='nearest', cmap='Blues')
    ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=class_labels,
           yticklabels=class_labels,
           ylabel='True Label',
           xlabel='Predicted Label',
           title='XGBoost Confusion Matrix on CIC-IDS2017')

    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    # Add text annotations
    thresh = cm_normalized.max() / 2.
    for i in range(cm_normalized.shape[0]):
        for j in range(cm_normalized.shape[1]):
            val = cm_normalized[i, j]
            count = cm[i, j]
            if count > 0:
                text = f'{val:.2%}\n({count})'
            else:
                text = ''
            ax.text(j, i, text,
                    ha="center", va="center", fontsize=7,
                    color="white" if val > thresh else "black")

    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
    print("\nSaved: confusion_matrix.png")
    plt.close()


def generate_latency_chart():
    """Generate per-stage latency comparison bar chart."""
    stages = ['Smart\nContracts', 'Off-Chain\nStorage', 'PBFT\nConsensus', 'Block\nMining']
    latencies = [0.081, 4.122, 1.664, 1.428]
    colors = ['#2196F3', '#4CAF50', '#FF9800', '#9C27B0']

    fig, ax = plt.subplots(figsize=(8, 5))

    bars = ax.bar(stages, latencies, color=colors, width=0.6, edgecolor='white', linewidth=1.5)

    # Add value labels on bars
    for bar, val in zip(bars, latencies):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.08,
                f'{val:.3f} ms', ha='center', va='bottom', fontsize=11, fontweight='bold')

    ax.set_ylabel('Average Latency (ms)', fontsize=12, fontweight='bold')
    ax.set_title('B-NIDS Blockchain Pipeline: Per-Stage Latency', fontsize=13, fontweight='bold')
    ax.set_ylim(0, max(latencies) * 1.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

    # Add total annotation
    total = sum(latencies)
    ax.annotate(f'Total Pipeline: {16.275:.1f} ms\n(incl. overhead)',
                xy=(0.95, 0.95), xycoords='axes fraction',
                ha='right', va='top', fontsize=10,
                bbox=dict(boxstyle='round,pad=0.5', facecolor='lightyellow', edgecolor='gray'))

    plt.tight_layout()
    plt.savefig('latency_chart.png', dpi=300, bbox_inches='tight')
    print("Saved: latency_chart.png")
    plt.close()


def generate_model_comparison():
    """Generate model comparison bar chart."""
    with open('models/model_results.json') as f:
        results = json.load(f)

    models = list(results.keys())
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']

    x = np.arange(len(models))
    width = 0.2
    colors = ['#1976D2', '#388E3C', '#F57C00', '#7B1FA2']

    fig, ax = plt.subplots(figsize=(10, 6))

    for i, metric in enumerate(metrics):
        values = [results[m][metric] * 100 for m in models]
        bars = ax.bar(x + i * width, values, width, label=metric, color=colors[i])
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                    f'{val:.2f}', ha='center', va='bottom', fontsize=7, fontweight='bold')

    ax.set_ylabel('Score (%)', fontsize=12, fontweight='bold')
    ax.set_title('ML Model Performance Comparison on CIC-IDS2017', fontsize=13, fontweight='bold')
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(models, fontsize=11)
    ax.legend(loc='lower right', fontsize=10)
    ax.set_ylim(99.7, 100.05)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('model_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: model_comparison.png")
    plt.close()


if __name__ == "__main__":
    generate_confusion_matrix()
    generate_latency_chart()
    generate_model_comparison()
    print("\nAll figures generated!")

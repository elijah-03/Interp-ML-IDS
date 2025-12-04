import matplotlib.pyplot as plt
import matplotlib.patches as patches

import numpy as np
import os

# Ensure figures directory exists
FIGURE_DIR = "docs/Latex/figures"
os.makedirs(FIGURE_DIR, exist_ok=True)

# Set global font
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]


def add_shadow(patch, ax, offset=(0.05, -0.05), color="gray", alpha=0.3):
    """Adds a drop shadow to a patch."""
    shadow = patches.FancyBboxPatch(
        (patch.get_x() + offset[0], patch.get_y() + offset[1]),
        patch.get_width(),
        patch.get_height(),
        boxstyle=patch.get_boxstyle(),
        facecolor=color,
        edgecolor="none",
        alpha=alpha,
        zorder=patch.get_zorder() - 1,
    )
    ax.add_patch(shadow)


def plot_system_architecture():
    """Generates a high-quality System Architecture Diagram."""
    fig, ax = plt.subplots(figsize=(12, 4.5))
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 4.5)
    ax.axis("off")

    # Styles
    styles = {
        "data": {"facecolor": "#f5f5f5", "edgecolor": "#9e9e9e"},
        "pipeline": {"facecolor": "#e3f2fd", "edgecolor": "#2196f3"},
        "model": {"facecolor": "#f3e5f5", "edgecolor": "#9c27b0"},
        "dashboard": {"facecolor": "#e0f2f1", "edgecolor": "#009688"},
        # zorder=20 ensures text is always on top of boxes
        "text": {
            "ha": "center",
            "va": "center",
            "fontsize": 10,
            "fontweight": "bold",
            "color": "#333333",
            "zorder": 20,
        },
    }

    # 1. Data Source
    data_box = patches.FancyBboxPatch(
        (0.5, 1.5),
        2.0,
        1.5,
        boxstyle="round,pad=0.1",
        linewidth=1.5,
        zorder=10,
        **styles["data"],
    )
    add_shadow(data_box, ax)
    ax.add_patch(data_box)
    ax.text(1.5, 2.25, "CSE-CIC-IDS2018\nDataset", **styles["text"])

    # 2. Data Pipeline Container
    pipeline_frame = patches.FancyBboxPatch(
        (3.2, 0.5),
        2.8,
        3.5,
        boxstyle="round,pad=0.1",
        linewidth=1.5,
        edgecolor="#90caf9",
        facecolor="#ffffff",
        linestyle="--",
        zorder=5,
    )
    ax.add_patch(pipeline_frame)
    ax.text(
        4.6,
        3.7,
        "Data Pipeline",
        ha="center",
        fontsize=10,
        fontweight="bold",
        color="#1565c0",
        zorder=20,
    )

    # Pipeline Steps
    step1 = patches.FancyBboxPatch(
        (3.5, 2.3),
        2.2,
        0.8,
        boxstyle="round,pad=0.1",
        linewidth=1,
        zorder=10,
        **styles["pipeline"],
    )
    add_shadow(step1, ax)
    ax.add_patch(step1)
    ax.text(
        4.6,
        2.7,
        "Preprocessing\n(Cleaning)",
        fontsize=9,
        ha="center",
        va="center",
        zorder=20,
    )

    step2 = patches.FancyBboxPatch(
        (3.5, 1.0),
        2.2,
        0.8,
        boxstyle="round,pad=0.1",
        linewidth=1,
        zorder=10,
        **styles["pipeline"],
    )
    add_shadow(step2, ax)
    ax.add_patch(step2)
    ax.text(
        4.6,
        1.4,
        "Feature Eng.\n& SMOTE",
        fontsize=9,
        ha="center",
        va="center",
        zorder=20,
    )

    # Arrow between pipeline steps
    ax.annotate(
        "",
        xy=(4.6, 1.8),
        xytext=(4.6, 2.3),
        arrowprops=dict(arrowstyle="->", color="#1565c0", lw=1.5),
        zorder=15,
    )

    # 3. Detection Engine
    model_box = patches.FancyBboxPatch(
        (6.8, 1.5),
        2.2,
        1.5,
        boxstyle="round,pad=0.1",
        linewidth=1.5,
        zorder=10,
        **styles["model"],
    )
    add_shadow(model_box, ax)
    ax.add_patch(model_box)
    ax.text(7.9, 2.25, "XGBoost\nClassifier", **styles["text"])

    # 4. Interactive Dashboard
    dash_box = patches.FancyBboxPatch(
        (10.0, 1.5),
        2.2,
        1.5,
        boxstyle="round,pad=0.1",
        linewidth=1.5,
        zorder=10,
        **styles["dashboard"],
    )
    add_shadow(dash_box, ax)
    ax.add_patch(dash_box)
    ax.text(11.1, 2.25, "Interactive\nDashboard", **styles["text"])

    # Main Flow Arrows
    arrow_style = dict(
        arrowstyle="simple,tail_width=0.5,head_width=1.2,head_length=1.0",
        color="#555555",
    )

    # Data -> Pipeline
    ax.annotate(
        "", xy=(3.2, 2.25), xytext=(2.5, 2.25), arrowprops=arrow_style, zorder=15
    )

    # Pipeline -> Model
    ax.annotate(
        "", xy=(6.8, 2.25), xytext=(6.0, 2.25), arrowprops=arrow_style, zorder=15
    )

    # Model -> Dashboard
    ax.annotate(
        "", xy=(10.0, 2.25), xytext=(9.0, 2.25), arrowprops=arrow_style, zorder=15
    )

    # Feedback Loop
    path_x = [7.9, 7.9, 11.1, 11.1]
    path_y = [1.5, 0.8, 0.8, 1.5]

    ax.plot(path_x, path_y, color="#333333", linewidth=1.5, linestyle="-", zorder=1)
    ax.annotate(
        "",
        xy=(11.1, 1.5),
        xytext=(11.1, 1.0),
        arrowprops=dict(arrowstyle="->", linewidth=1.5, color="#333333"),
        zorder=1,
    )

    # Label on the feedback line
    bbox_props = dict(boxstyle="round,pad=0.3", fc="white", ec="#333333", alpha=1.0)
    ax.text(
        9.5,
        0.8,
        "SHAP Explanations\n& Counterfactuals",
        ha="center",
        va="center",
        fontsize=9,
        bbox=bbox_props,
        zorder=20,
    )

    plt.tight_layout()
    plt.savefig(
        os.path.join(FIGURE_DIR, "system_architecture.png"),
        dpi=300,
        bbox_inches="tight",
    )
    plt.close()


def plot_shap_waterfall():
    """Generates a professional SHAP Waterfall Plot."""
    RED = "#ff0051"
    BLUE = "#008bfb"

    features = ["Dst Port (80)", "Packet Rate", "SYN Flag Count", "Flow Duration"]
    contributions = [-0.8, 1.2, 2.5, 3.8]
    base_value = -2.5

    values = [base_value]
    for c in contributions:
        values.append(values[-1] + c)
    final_value = values[-1]

    fig, ax = plt.subplots(figsize=(9, 4.5))

    # Adjust x-limits to ensure room for labels on the left
    min_val = min(values) - 1.0
    max_val = max(values) + 1.0
    ax.set_xlim(min_val, max_val)

    y_pos = np.arange(len(features))

    # E[f(x)] line
    ax.axvline(x=base_value, color="#aaaaaa", linestyle="--", linewidth=1, zorder=0)
    ax.text(
        base_value,
        -0.8,
        f"E[f(x)] = {base_value:.1f}",
        ha="center",
        va="top",
        fontsize=10,
        color="#555555",
    )

    for i, (feat, contrib) in enumerate(zip(features, contributions)):
        start = values[i]
        end = values[i + 1]
        color = RED if contrib > 0 else BLUE

        # Bar
        ax.barh(
            i,
            contrib,
            left=start,
            color=color,
            height=0.5,
            align="center",
            edgecolor="none",
            zorder=3,
        )

        # Connector line
        if i < len(features) - 1:
            ax.plot(
                [end, end],
                [i, i + 1],
                color="#aaaaaa",
                linestyle="-",
                linewidth=1,
                zorder=1,
            )

        # Value Label
        # Add a bit more padding to text_x
        padding = 0.4 if contrib > 0 else -0.4
        text_x = end + padding

        ax.text(
            text_x,
            i,
            f"{contrib:+.1f}",
            va="center",
            ha="left" if contrib > 0 else "right",
            fontsize=10,
            color=color,
            fontweight="bold",
        )

    # f(x) line
    ax.axvline(x=final_value, color="#333333", linestyle="-", linewidth=1, zorder=0)
    ax.text(
        final_value,
        len(features) - 0.5,
        f"f(x) = {final_value:.1f}",
        ha="center",
        va="bottom",
        fontsize=11,
        fontweight="bold",
    )

    ax.set_yticks(y_pos)
    ax.set_yticklabels(features, fontsize=11)
    ax.set_xlabel("SHAP Value (Log-Odds Impact)", fontsize=10)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_color("#aaaaaa")

    ax.grid(axis="x", linestyle=":", alpha=0.3)

    plt.tight_layout()
    plt.savefig(
        os.path.join(FIGURE_DIR, "shap_explanation.png"), dpi=300, bbox_inches="tight"
    )
    plt.close()


if __name__ == "__main__":
    plot_system_architecture()
    plot_shap_waterfall()

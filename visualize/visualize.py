import os
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from collections import defaultdict

RESULTS_FILE = os.environ.get("RESULTS_FILE", "/results/benchmark_results.csv")
OUTPUT_DIR   = os.environ.get("OUTPUT_DIR",   "/results/charts")

os.makedirs(OUTPUT_DIR, exist_ok=True)

rows = []
with open(RESULTS_FILE, newline="") as f:
    for row in csv.DictReader(f):
        rows.append({
            "language":     row["language"],
            "algorithm":    row["algorithm"],
            "size_mb":      int(row["file_size_mb"]),
            "encrypt_ms":   float(row["encrypt_ms"]),
            "decrypt_ms":   float(row["decrypt_ms"]),
            "ram_mb":       float(row["ram_used_mb"]),
            "integrity":    row["integrity_ok"],
        })

languages  = sorted(set(r["language"]  for r in rows))
algorithms = sorted(set(r["algorithm"] for r in rows))
sizes      = sorted(set(r["size_mb"]   for r in rows))

COLORS = {
    "Java":        "#f89820",
    "CSharp":      "#9b4f96",
    "Python":      "#3572A5",
    "Python-pure": "#e05d44",
}

def color(lang):
    return COLORS.get(lang, "#888888")

def get(lang, algo, size, field):
    for r in rows:
        if r["language"] == lang and r["algorithm"] == algo and r["size_mb"] == size:
            return r[field]
    return None


for size in sizes:
    for metric, label in [("encrypt_ms", "Szyfrowanie"), ("decrypt_ms", "Deszyfrowanie")]:
        fig, axes = plt.subplots(1, len(algorithms), figsize=(6 * len(algorithms), 5), sharey=False)
        if len(algorithms) == 1:
            axes = [axes]

        fig.suptitle(f"{label} — {size} MB", fontsize=14, fontweight="bold")

        for ax, algo in zip(axes, algorithms):
            vals  = [get(lang, algo, size, metric) or 0 for lang in languages]
            bars  = ax.bar(languages, vals, color=[color(l) for l in languages], width=0.5, edgecolor="white")

            for bar, val in zip(bars, vals):
                if val > 0:
                    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.01,
                            f"{val:.0f} ms", ha="center", va="bottom", fontsize=9)

            ax.set_title(algo, fontsize=11)
            ax.set_ylabel("Czas [ms]")
            ax.set_ylim(0, max(vals) * 1.15 if max(vals) > 0 else 1)
            ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:.0f}"))
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

        plt.tight_layout()
        fname = f"bar_{metric}_{size}mb.png"
        plt.savefig(os.path.join(OUTPUT_DIR, fname), dpi=150, bbox_inches="tight")
        plt.close()
        print(f"Zapisano: {fname}")


for algo in algorithms:
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle(f"Skalowanie — {algo}", fontsize=14, fontweight="bold")

    for ax, (metric, label) in zip(axes, [("encrypt_ms", "Szyfrowanie"), ("decrypt_ms", "Deszyfrowanie")]):
        for lang in languages:
            lang_sizes = []
            lang_vals  = []
            for size in sizes:
                val = get(lang, algo, size, metric)
                if val is not None:
                    lang_sizes.append(size)
                    lang_vals.append(val)
            if lang_vals:
                ax.plot(lang_sizes, lang_vals, marker="o", label=lang,
                        color=color(lang), linewidth=2, markersize=6)
                for x, y in zip(lang_sizes, lang_vals):
                    ax.annotate(f"{y:.0f}", (x, y), textcoords="offset points",
                                xytext=(0, 8), ha="center", fontsize=8, color=color(lang))

        ax.set_title(label)
        ax.set_xlabel("Rozmiar pliku [MB]")
        ax.set_ylabel("Czas [ms]")
        ax.set_xscale("log")
        ax.set_xticks(sizes)
        ax.get_xaxis().set_major_formatter(ticker.ScalarFormatter())
        ax.legend()
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fname = f"line_{algo.replace('-', '_').replace(' ', '_')}.png"
    plt.savefig(os.path.join(OUTPUT_DIR, fname), dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Zapisano: {fname}")


for size in sizes:
    fig, axes = plt.subplots(1, len(algorithms), figsize=(6 * len(algorithms), 5), sharey=True)
    if len(algorithms) == 1:
        axes = [axes]

    fig.suptitle(f"Zużycie RAM — {size} MB", fontsize=14, fontweight="bold")

    for ax, algo in zip(axes, algorithms):
        vals = [get(lang, algo, size, "ram_mb") or 0 for lang in languages]
        bars = ax.bar(languages, vals, color=[color(l) for l in languages], width=0.5, edgecolor="white")

        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.01,
                        f"{val:.0f} MB", ha="center", va="bottom", fontsize=9)

        ax.set_title(algo, fontsize=11)
        ax.set_ylabel("RAM [MB]")
        ax.set_ylim(0, max(vals) * 1.15 if max(vals) > 0 else 1)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    plt.tight_layout()
    fname = f"bar_ram_{size}mb.png"
    plt.savefig(os.path.join(OUTPUT_DIR, fname), dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Zapisano: {fname}")

print(f"\n=== Wizualizacja zakończona. Wykresy w: {OUTPUT_DIR} ===")
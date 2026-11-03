from __future__ import annotations

from CyberBotRuntimeModule import *

def plotBarCharts(datasets: list[dict], xLabels: list[str], suptitle: str, savePath: str) -> None:
    """
    Description: Plotting three bar charts representing Total Input Tokens, Total Output Tokens and Total Costs
    :param datasets: The list of all y values for each bar chart
    :param xLabels: The x label for each bar chart
    :param suptitle: The Main Title for all the bar charts
    :param savePath: The path to save the bar charts
    :return: None, the bar charts will be saved in the savePath
    """
    def formatFinalValue(val):
        if val == int(val):
            return f"{int(val):,}"
        else:
            return str(val)
    x = np.arange(len(xLabels))
    barWidth = 0.55
    fig, axes = plt.subplots(3, 1, figsize=(13, 13))
    fig.patch.set_facecolor("#F7F8FA")
    fig.suptitle(suptitle, fontsize=17, fontweight="bold", color="#1E2A3A", y=0.98)
    for ax, ds in zip(axes, datasets):
        values = ds["values"]
        color = ds["color"]
        max_v = max(values) if any(v > 0 for v in values) else 1
        bars = ax.bar(x, values, width=barWidth, color=color, alpha=0.88, edgecolor="white", linewidth=0.8, zorder=3)
        ax.set_facecolor("#F7F8FA")
        if ds["title"] == "Total Input Tokens":
            title = f"Total Input Tokens: {formatFinalValue(sum(values))} tokens"
        elif ds["title"] == "Total Output Tokens":
            title = f"Total Output Tokens: {formatFinalValue(sum(values))} tokens"
        else:
            title = f"Total Cost: ${formatFinalValue(round(sum(values), 5))}"
        ax.set_title(title, fontsize=13, fontweight="bold", color="#1E2A3A", pad=8, loc="left")
        ax.set_xticks(x)
        ax.set_xticklabels(xLabels, fontsize=10, color="#444")
        ax.tick_params(axis="y", labelsize=9, colors="#666")
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.spines[["top", "right", "left"]].set_visible(False)
        ax.spines["bottom"].set_color("#DDD")
        ax.yaxis.grid(True, color="#E0E0E0", linewidth=0.7, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", length=0)
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_v * 0.015, f"{val:,}", ha="center", va="bottom", fontsize=7.5, color="#333", fontweight="500")
        for i, val in enumerate(values):
            if val == 0:
                ax.axvspan(i - barWidth / 2, i + barWidth / 2, color="#E8E8E8", alpha=0.5, zorder=1)
    plt.savefig(savePath, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def plotModelCalls(LLMModels: list[str], LLMModelUses: list[int], savePath: str):
    """
    Description: Plotting a single bar chart showing the total calls per LLM models each month
    :param LLMModels: The list of all the LLM models that has been used at least one
    :param LLMModelUses: The usage value of each LLM models
    :param savePath: The path to save the bar chart
    :return: None, the bar chart will be saved in the savePath
    """

    x = np.arange(len(LLMModels))
    max_val = max(LLMModelUses) if any(LLMModelUses) else 2

    fig, ax = plt.subplots(figsize=(10, 7))
    fig.patch.set_facecolor("#F7F8FA")

    bars = ax.bar(LLMModels, LLMModelUses, width=0.55, color="Purple", alpha=0.88, edgecolor="white", linewidth=0.8, zorder=3)
    ax.set_facecolor("#F7F8FA")
    ax.set_title("LLM Model Calls", fontsize=13, fontweight="bold", color="#1E2A3A", pad=8, loc="left")
    ax.set_xticks(x)
    ax.set_xticklabels(LLMModels, fontsize=10, color="#444", rotation=40, ha="right")
    ax.tick_params(axis="y", labelsize=9, colors="#666")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color("#DDD")
    ax.yaxis.grid(True, color="#E0E0E0", linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="x", length=0)
    for bar, val in zip(bars, LLMModelUses):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_val * 0.015, f"{val:,}", ha="center", va="bottom", fontsize=7.5, color="#333", fontweight="500")

    for i, val in enumerate(LLMModelUses):
        if val == 0:
            ax.axvspan(i - 0.55 / 2, i + 0.55 / 2, color="#E8E8E8", alpha=0.5, zorder=1)
    ax.set_ylim(0, max_val * 1.35)
    plt.savefig(savePath, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


async def writingLLMUsageCsv(csvPath: str, mode: Literal['w', 'a'], data: list, ObjectLock: asyncio.locks.Lock) -> None:
    """
    Description: Executing read and write only operation on the csv files related to logging Cyberbot LLM Usage
    :param csvPath: The path to the csv file
    :param mode: Must be 'w' or 'a'
    :param data: The data to write
    :param ObjectLock: Object lock on write operation to prevent race condition
    :return: None
    """
    async with ObjectLock:
        async with aiofiles.open(csvPath, mode) as f:
            csvWriter = AsyncWriter(f)
            await csvWriter.writerow(data)


def calculateUsageCost(model: str, InputTokens: list, totalOutputTokens: int) -> float:
    """
    Description: Calculate the usage cost of the LLM model based on the total input tokens and output tokens.
    :param model: LLM Model
    :param InputTokens: The list of total input tokens [raw, cached read] of a prompt
    :param totalOutputTokens: The total output tokens of a prompt
    :return: The final calculated usage cost
    """
    totalInputTokens = sum(InputTokens)
    totalRawInputTokens =  InputTokens[0]
    totalCachedReadTokens = InputTokens[1]
    if "gemini" in model:
        InputCostIndex = 1 if totalInputTokens > 200000 else 0
        OutputCostIndex = 1 if totalOutputTokens > 200000 else 0
    else:
        InputCostIndex = 0
        OutputCostIndex = 0
    totalRawInputCost = (totalRawInputTokens / 1000000) * LLM_MODEL_INFORMATION[model]["Cost"]["Input Token"][InputCostIndex]
    totalCachedReadCost = (totalCachedReadTokens / 1000000) * LLM_MODEL_INFORMATION[model]["Cost"]["Cached Read"][InputCostIndex]
    totalOutputTokens = (totalOutputTokens / 1000000) * LLM_MODEL_INFORMATION[model]["Cost"]["Output Token"][OutputCostIndex]
    totalCost = round(totalRawInputCost + totalCachedReadCost + totalOutputTokens, 5)
    return totalCost

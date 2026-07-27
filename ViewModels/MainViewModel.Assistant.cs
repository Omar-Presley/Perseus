using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Perseus.Reporting;
using Perseus.Services;

namespace Perseus.ViewModels;

public sealed class ChatMessageViewModel : ViewModelBase
{
    public ChatMessageViewModel(string role, string text)
    {
        Role = role;
        _text = text;
        Timestamp = DateTime.Now;
    }

    public string Role { get; }
    public bool IsUser => Role == "You";
    public DateTime Timestamp { get; }

    private string _text;
    public string Text
    {
        get => _text;
        set => SetProperty(ref _text, value);
    }
}

public partial class MainViewModel
{
    private bool _isAssistantResponding;
    private bool _hasAnthropicApiKey;
    private string _assistantInputText = string.Empty;

    public ObservableCollection<ChatMessageViewModel> AssistantMessages { get; } = new();

    public AsyncRelayCommand SendAssistantMessageCommand { get; private set; } = null!;
    public RelayCommand ClearAssistantChatCommand { get; private set; } = null!;
    public RelayCommand AskAiAboutFindingCommand { get; private set; } = null!;

    public string AssistantInputText
    {
        get => _assistantInputText;
        set => SetProperty(ref _assistantInputText, value);
    }

    public bool IsAssistantResponding
    {
        get => _isAssistantResponding;
        set => SetProperty(ref _isAssistantResponding, value);
    }

    public bool HasAnthropicApiKey
    {
        get => _hasAnthropicApiKey;
        set => SetProperty(ref _hasAnthropicApiKey, value);
    }

    private void InitializeAssistantState()
    {
        SendAssistantMessageCommand = new AsyncRelayCommand(async _ => await SendAssistantMessageAsync());
        ClearAssistantChatCommand = new RelayCommand(_ => AssistantMessages.Clear());
        AskAiAboutFindingCommand = new RelayCommand(p =>
        {
            if (p is not Finding finding) return;

            AssistantInputText =
                $"Explain this finding and give me step-by-step remediation guidance for {PlatformLabel}:\n" +
                $"Category: {finding.Category}\n" +
                $"Name: {finding.Name}\n" +
                $"Severity: {finding.Severity}\n" +
                $"Status: {finding.Status}\n" +
                $"Detail: {finding.Detail}\n" +
                $"Existing recommendation: {finding.Recommendation}";

            SelectedTabIndex = AssistantTabIndex;
            SendAssistantMessageCommand.Execute(null);
        });
    }

    private void UpdateHasAnthropicApiKey()
    {
        HasAnthropicApiKey = !string.IsNullOrWhiteSpace(AnthropicApiKeySetting);
    }

    private async Task SendAssistantMessageAsync()
    {
        if (IsAssistantResponding || !HasAnthropicApiKey) return;

        var question = AssistantInputText.Trim();
        if (string.IsNullOrEmpty(question)) return;

        AssistantInputText = string.Empty;
        AssistantMessages.Add(new ChatMessageViewModel("You", question));
        var reply = new ChatMessageViewModel("Claude", string.Empty);
        AssistantMessages.Add(reply);

        IsAssistantResponding = true;
        try
        {
            var history = AssistantMessages
                .Where(m => m.Role != "System")
                .Select(m => (m.Role, m.Text))
                .ToList();

            await foreach (var delta in ClaudeRemediationService.StreamReplyAsync(AnthropicApiKeySetting, BuildAssistantSystemPrompt(), history))
            {
                reply.Text += delta;
            }

            if (string.IsNullOrEmpty(reply.Text))
            {
                reply.Text = "(No response text was returned.)";
            }
        }
        catch (ClaudeRequestException ex)
        {
            reply.Text = ex.Message;
            AddLog($"AI Assistant error: {ex.Message}");
        }
        catch (Exception ex)
        {
            reply.Text = $"Unexpected error: {ex.Message}";
            AddLog($"AI Assistant error: {ex.Message}");
        }
        finally
        {
            IsAssistantResponding = false;
        }
    }

    private string BuildAssistantSystemPrompt()
    {
        return
            "You are a security remediation assistant embedded in Perseus, a cross-platform endpoint " +
            "security audit tool. The user is a system administrator reviewing audit findings on a " +
            $"{PlatformLabel} endpoint. Give clear, actionable remediation guidance: concrete commands " +
            "or configuration steps for their platform, ordered by priority, noting the risk each fix " +
            "addresses. Be concise but complete. You are advisory only - you cannot run commands " +
            "yourself, so tell the user what to run rather than claiming to have done it. If a finding " +
            "is a simple outdated package, mention that Perseus's Remediation tab can apply OS package " +
            "upgrades directly via winget/apt/brew.\n\n" +
            $"Current audit snapshot: overall score {OverallScore}/100 ({RiskLevel}), " +
            $"{CriticalCount} critical, {HighCount} high, {MediumCount} medium, {LowCount} low severity findings.";
    }
}

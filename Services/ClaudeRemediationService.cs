using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Anthropic;
using Anthropic.Exceptions;
using Anthropic.Models.Messages;

namespace Perseus.Services;

public sealed class ClaudeRequestException : Exception
{
    public ClaudeRequestException(string message, Exception? inner = null) : base(message, inner) { }
}

public static class ClaudeRemediationService
{
    private const string Model = "claude-opus-5";

    public static async IAsyncEnumerable<string> StreamReplyAsync(
        string apiKey,
        string systemPrompt,
        IReadOnlyList<(string Role, string Text)> history,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        AnthropicClient client = new() { ApiKey = apiKey };

        var messages = new List<MessageParam>();
        foreach (var (role, text) in history)
        {
            messages.Add(new MessageParam
            {
                Role = role == "You" ? Role.User : Role.Assistant,
                Content = text
            });
        }

        var parameters = new MessageCreateParams
        {
            Model = Model,
            MaxTokens = 4096,
            System = systemPrompt,
            Messages = messages
        };

        IAsyncEnumerator<RawMessageStreamEvent> enumerator;
        try
        {
            enumerator = client.Messages.CreateStreaming(parameters).GetAsyncEnumerator(ct);
        }
        catch (Exception ex)
        {
            throw Translate(ex);
        }

        try
        {
            while (true)
            {
                bool hasNext;
                try
                {
                    hasNext = await enumerator.MoveNextAsync();
                }
                catch (Exception ex)
                {
                    throw Translate(ex);
                }

                if (!hasNext) yield break;

                var evt = enumerator.Current;
                if (evt.TryPickContentBlockDelta(out var delta) && delta.Delta.TryPickText(out var text))
                {
                    yield return text.Text;
                }
            }
        }
        finally
        {
            await enumerator.DisposeAsync();
        }
    }

    private static ClaudeRequestException Translate(Exception ex) => ex switch
    {
        AnthropicUnauthorizedException => new ClaudeRequestException(
            "Anthropic rejected the API key (401). Check the key in Settings.", ex),
        AnthropicRateLimitException => new ClaudeRequestException(
            "Rate limited by the Anthropic API (429). Try again in a moment.", ex),
        Anthropic5xxException => new ClaudeRequestException(
            "Anthropic's API had a server error. Try again shortly.", ex),
        AnthropicIOException => new ClaudeRequestException(
            "Could not reach the Anthropic API - check your network connection.", ex),
        AnthropicApiException apiEx => new ClaudeRequestException(
            $"Anthropic API error: {apiEx.Message}", ex),
        _ => new ClaudeRequestException($"Unexpected error: {ex.Message}", ex)
    };
}

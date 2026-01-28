// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GerritChangeInput is the structure for the POST body to create a change.
type GerritChangeInput struct {
	Project string            `json:"project"`
	Branch  string            `json:"branch"`
	Subject string            `json:"subject"`	
	BaseCommit    string            `json:"base_commit,omitempty"`
	Patch *ApplyPatchInput `json:"patch,omitempty"`
}

type ApplyPatchInput struct {
	Patch string `json:"patch"`
}

// GerritChangeInfo parses the essential details from the Gerrit API response.
type GerritChangeInfo struct {
	ID      string `json:"id"`
	Number  int    `json:"_number"`
	Project string `json:"project"`
	Branch  string `json:"branch"`
	Status  string `json:"status"`
	WebURL  string `json:"_sortkey"` // Contains a URL to the change in Gerrit UI
}

// createGerritChange uses the Gerrit REST API to create a new change with specified file contents.
// files: A map where keys are depot-relative file paths (e.g., "src/main.go")
// and values are the full string content of each file.
func createGerritChange(ctx context.Context, host, project, branch, subject string) (*GerritChangeInfo, error) {
	// 1. Get an authenticated HTTP client using the App Engine service account's credentials.
	// The "https://www.googleapis.com/auth/gerritcodereview" scope is required.
	ts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/gerritcodereview")
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}
	httpClient := oauth2.NewClient(ctx, ts)

	// 3. Construct the request payload.
	changeInput := GerritChangeInput{
		Project: project,
		Branch:  branch,
		Subject: `ALSA: aloop: Fix use-after-free in loopback_check_format

KASAN reports a use-after-free in rt_spin_lock when snd_pcm_stop is
called from loopback_check_format:

---
Change-Id: If5bb8de4a596d4cbf92bbb4afd3d371422577d0f
`,
		BaseCommit: "63804fed149a6750ffd28610c5c1c98cce6bd377",
		Patch: &ApplyPatchInput{
			Patch: `diff --git a/sound/drivers/aloop.c b/sound/drivers/aloop.c
index 64ef03b2d579..dfb4409bd83f 100644
--- a/sound/drivers/aloop.c
+++ b/sound/drivers/aloop.c
@@ -341,9 +341,11 @@ static int loopback_check_format(struct loopback_cable *cable, int stream)
 	struct snd_card *card;
 	int check;
 
+	spin_lock(&cable->lock);
 	if (cable->valid != CABLE_VALID_BOTH) {
 		if (stream == SNDRV_PCM_STREAM_PLAYBACK)
 			goto __notify;
+		spin_unlock(&cable->lock);
 		return 0;
 	}
 	runtime = cable->streams[SNDRV_PCM_STREAM_PLAYBACK]->
@@ -355,39 +357,39 @@ static int loopback_check_format(struct loopback_cable *cable, int stream)
 		runtime->channels != cruntime->channels ||
 		is_access_interleaved(runtime->access) !=
 		is_access_interleaved(cruntime->access);
-	if (!check)
+	if (!check) {
+		spin_unlock(&cable->lock);
 		return 0;
-	if (stream == SNDRV_PCM_STREAM_CAPTURE) {
-		return -EIO;
-	} else {
-		snd_pcm_stop(cable->streams[SNDRV_PCM_STREAM_CAPTURE]->
-					substream, SNDRV_PCM_STATE_DRAINING);
-	      __notify:
-		runtime = cable->streams[SNDRV_PCM_STREAM_PLAYBACK]->
+	}
+	spin_unlock(&cable->lock);
+	return -EIO;
+
+      __notify:
+	spin_unlock(&cable->lock);
+	runtime = cable->streams[SNDRV_PCM_STREAM_PLAYBACK]->
 							substream->runtime;
-		setup = get_setup(cable->streams[SNDRV_PCM_STREAM_PLAYBACK]);
-		card = cable->streams[SNDRV_PCM_STREAM_PLAYBACK]->loopback->card;
-		if (setup->format != runtime->format) {
-			snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
-							&setup->format_id);
-			setup->format = runtime->format;
-		}
-		if (setup->rate != runtime->rate) {
-			snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
-							&setup->rate_id);
-			setup->rate = runtime->rate;
-		}
-		if (setup->channels != runtime->channels) {
-			snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
-							&setup->channels_id);
-			setup->channels = runtime->channels;
-		}
-		if (is_access_interleaved(setup->access) !=
-		    is_access_interleaved(runtime->access)) {
-			snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
-							&setup->access_id);
-			setup->access = runtime->access;
-		}
+	setup = get_setup(cable->streams[SNDRV_PCM_STREAM_PLAYBACK]);
+	card = cable->streams[SNDRV_PCM_STREAM_PLAYBACK]->loopback->card;
+	if (setup->format != runtime->format) {
+		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
+						&setup->format_id);
+		setup->format = runtime->format;
+	}
+	if (setup->rate != runtime->rate) {
+		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
+						&setup->rate_id);
+		setup->rate = runtime->rate;
+	}
+	if (setup->channels != runtime->channels) {
+		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
+						&setup->channels_id);
+		setup->channels = runtime->channels;
+	}
+	if (is_access_interleaved(setup->access) !=
+	    is_access_interleaved(runtime->access)) {
+		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
+						&setup->access_id);
+		setup->access = runtime->access;
 	}
 	return 0;
 }
`,
		},
	}

	jsonData, err := json.Marshal(changeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// 4. Build the POST request to the Gerrit Create Change endpoint.
	// The "/a/" prefix is crucial for authenticated API access.
	endpoint := fmt.Sprintf("https://%s-review.googlesource.com/a/changes/", host)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	// 5. Execute the request.
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Gerrit Create Change API: %w", err)
	}
	defer resp.Body.Close()

	// 6. Handle the API response. A 201 Created status indicates success.
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("gerrit API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Gerrit API responses may start with ")]}'" for XSSI protection; trim it.
	const magicPrefix = ")]}'\n"
	if bytes.HasPrefix(bodyBytes, []byte(magicPrefix)) {
		bodyBytes = bodyBytes[len(magicPrefix):]
	}

	var changeInfo GerritChangeInfo
	if err := json.Unmarshal(bodyBytes, &changeInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &changeInfo, nil
}

func createCodereview(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	myHost := "linux"
	myProject := "linux/kernel/git/torvalds/linux"
	myBranch := "master"
	mySubject := "test: change"

	change, err := createGerritChange(ctx, myHost, myProject, myBranch, mySubject)
	if err != nil {
		return fmt.Errorf("failed to create Gerrit change: %w", err)
	}

	responseMsg := fmt.Sprintf("Successfully created Gerrit change %d (%s) in %s/%s. Review URL: %s",
		change.Number, change.ID, change.Project, change.Branch, change.WebURL)
	fmt.Fprintln(w, responseMsg)
	return nil
}

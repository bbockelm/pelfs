import { expect, test } from "./pelfs";

/**
 * WITH SCRIPTING OFF.
 *
 * Both surfaces are useless without JavaScript -- M1's page renders
 * everything from an SSE stream, and the file manager is a React app -- so
 * with scripting disabled a user gets a blank page, and a blank page from a
 * tool that is holding their unpublished data is alarming in exactly the
 * wrong way.
 *
 * The message costs one element and answers the only question that matters at
 * that moment: nothing is wrong with your data, the process in your terminal
 * still has it, and this is how you stop it.
 */
test("the page says something useful with JavaScript disabled", async ({ browser }) => {
  const context = await browser.newContext({
    javaScriptEnabled: false,
    baseURL: process.env.PELFS_WEBUI_URL,
  });
  const page = await context.newPage();
  await page.goto("/");

  const notice = page.getByTestId("noscript");
  await expect(notice).toBeVisible();
  // Not "enable JavaScript": the useful half is what is true about their data.
  await expect(notice).toContainText(/Nothing is wrong with your data/i);
  await expect(notice).toContainText("pelfs browse");
  await context.close();
});

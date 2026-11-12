import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSearchExcerpt } from "../../../ui/report-search-excerpt.js";

void test("search excerpts highlight every literal occurrence without injecting markup", () => {
  assert.equal(renderSearchExcerpt("<Name> name & NAME", "name"),
    "&lt;<mark>Name</mark>&gt; <mark>name</mark> &amp; <mark>NAME</mark>");
  assert.equal(renderSearchExcerpt("a.*b aZZb", "a.*b"), "<mark>a.*b</mark> aZZb");
});

void test("search excerpts preserve spaces and ignore only surrounding query whitespace", () => {
  assert.equal(renderSearchExcerpt("a b a  b", " a b "), "<mark>a b</mark> a  b");
  assert.equal(renderSearchExcerpt("a b a  b", "a  b"), "a b <mark>a  b</mark>");
  assert.equal(renderSearchExcerpt("a b", "  "), "a b");
});

void test("search excerpts handle Unicode and case folding without shifting the match", () => {
  assert.equal(renderSearchExcerpt("İ <Автор> ſ", "автор"), "İ &lt;<mark>Автор</mark>&gt; ſ");
  assert.equal(renderSearchExcerpt("İName", "name"), "İ<mark>Name</mark>");
});

void test("search excerpts show context around distant matches and mark truncated edges", () => {
  assert.equal(renderSearchExcerpt("x".repeat(100) + "needle" + "y".repeat(400), "needle"),
    "…" + "x".repeat(60) + "<mark>needle</mark>" + "y".repeat(294) + "…");
  assert.equal(renderSearchExcerpt("needle" + "x".repeat(354), "needle"),
    "<mark>needle</mark>" + "x".repeat(354));
  assert.equal(renderSearchExcerpt("absent", "needle"), "absent");
  assert.equal(renderSearchExcerpt("", "needle"), "");
});

void test("a phrase longer than the excerpt still receives one complete highlight", () => {
  const phrase = "long phrase ".repeat(40).trim();

  assert.equal(renderSearchExcerpt("x".repeat(100) + phrase + "tail", phrase),
    "…" + "x".repeat(60) + `<mark>${phrase}</mark>…`);
});

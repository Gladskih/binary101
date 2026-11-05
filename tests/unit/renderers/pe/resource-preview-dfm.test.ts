import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDfmPreview } from "../../../../renderers/pe/resource-preview-dfm.js";
import { addDfmPreview } from "../../../../analyzers/pe/resources/preview/dfm.js";
import { createDfmResource } from "../../../fixtures/pe-resource-advanced-payloads.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { addTextDfmPreview } from "../../../../analyzers/pe/resources/preview/dfm-text.js";
import { createNotebookDfmResource } from "../../../fixtures/pe-resource-dfm-payloads.js";

void test("renders Inno notebook pages, progress bars and static labels as their saved controls", () => {
  // TNewNotebookPage fills its notebook; its dimensions and visibility are not streamed.
  // https://github.com/jrsoftware/issrc/blob/main/Components/NewNotebook.pas
  const root = expectDefined(addTextDfmPreview(createNotebookDfmResource())?.preview?.dfm);
  const html = renderDfmPreview(root);

  assert.match(html, /data-pe-dfm-component="Installing"[^>]*width:389px;height:170px/);
  assert.match(html, /data-pe-dfm-component="Other"[^>]* hidden/);
  assert.match(html, /data-pe-dfm-component="HiddenLabel"[^>]* hidden/);
  assert.doesNotMatch(expectDefined(html.match(/<div[^>]*data-pe-dfm-component="Installing"[^>]*>/)?.[0]),
    / hidden|aria-disabled|font-size:0/);
  assert.doesNotMatch(expectDefined(html.match(/<div[^>]*data-pe-dfm-component="Progress"[^>]*>/)?.[0]),
    / hidden|aria-disabled|font-size:0/);
  assert.match(html, /<progress value="150" max="300"/);
  assert.match(html, /font-size:11px/);
  assert.match(html, /data-pe-dfm-component="NotebookPreview"[^>]*left:0px;top:0px;width:400px;height:240px/);
  assert.doesNotMatch(expectDefined(html.match(/<div[^>]*data-pe-dfm-component="Status"[^>]*>/)?.[0]),
    /white-space:pre-wrap/);
  assert.match(html, /peDfm__control--label/);
  assert.doesNotMatch(html.split("<table")[0]!, />Pages<|>Installing<|>Status<|>Progress</);
});
void test("renders saved DFM geometry with component/property evidence and escaped captions", () => {
  const root = expectDefined(addDfmPreview(createDfmResource())?.preview?.dfm);
  root.children[0]!.properties.push({name:"Text",value:{kind:"string",value:"<img src=x>"}});
  const html = renderDfmPreview(root);
  assert.match(html, /Main.Accept/);
  assert.match(html, /left:12px;top:16px/);
  assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<img src=x>/);
});

void test("renders the retained form value kinds and known component faces", () => {
  const root = expectDefined(addDfmPreview(createDfmResource())?.preview?.dfm);
  root.properties.push({name:"Raw",value:{kind:"binary",data:new Uint8Array(33)}},
    {name:"Extended",value:{kind:"extended",value:"00000000000000000000"}},
    {name:"Exact",value:{kind:"binary",data:Uint8Array.of(10, ...new Uint8Array(31))}},
    {name:"Null",value:{kind:"null"}},{name:"Set",value:{kind:"set",values:["One","Two"]}},
    {name:"List",value:{kind:"list",values:[]}},{name:"Items",value:{kind:"collection",items:[]}});
  root.children = ["TCheckBox","TCheckBox","TRadioButton","TProgressBar","TComboBox","TCustom"].map((className,index)=>({
    className,name:"Control"+index,flags:0,children:[],properties:[
      {name:"Checked",value:{kind:"boolean",value:index===0}},
      {name:"Left",value:{kind:"number",value:"Infinity"}},
      {name:"Text",value:{kind:"string",value:"Text"}}
    ]
  }));
  const html = renderDfmPreview(root);

  assert.match(html,/33 bytes/);
  assert.match(html, new RegExp("33 bytes: " + "00 ".repeat(31) + "00 …"));
  assert.match(html, new RegExp("32 bytes: 0a " + "00 ".repeat(30) + "00</div>"));
  assert.match(html,/One, Two/);
  assert.match(html,/x87 extended/);
  assert.match(html,/nil/);
  assert.match(html,/0 list items/);
  assert.match(html,/0 collection items/);
  assert.match(html,/<progress/);
  assert.match(html,/&#x2611; Text/);
  assert.match(html,/&#x2610; Text/);
  assert.match(html,/data-pe-dfm-component="Control0"[^>]*>&#x2611; Text/);
  assert.match(html,/data-pe-dfm-component="Control1"[^>]*>&#x2610; Text/);
  assert.match(html,/&#x25cb; Text/);
  assert.match(html,/Text <span class="peDfm__arrow">&#x25be;/);
  assert.doesNotMatch(html,/left:Infinity/);
});

void test("keeps empty captions empty and distinguishes visual controls from nonvisual components", () => {
  const root = expectDefined(addTextDfmPreview(`object Form: TForm
    object Panel: TPanel
      Width = 100
      Height = 40
      Color = clWindow
      object Empty: TNewStaticText
        Caption = ''
        WordWrap = True
        Alignment = taCenter
      end
    end
    object Image: TBitmapImage
      Width = 32
      Height = 32
    end
    object Timer: TTimer
      Left = 12
    end
    object Custom: constructor
      Width = 20
    end
    object Tall: TCustom
      Height = 30
    end
    object Bevel: TBevel
      Shape = bsTopLine
    end
    object Container: TCustomContainer
      Width = 100
      object Selected: TNewRadioButton
        Checked = True
        Caption = 'Selected'
      end
    end
  end`)?.preview?.dfm);
  const html = renderDfmPreview(root).split("<table")[0]!;

  assert.match(html, /peDfm__control--panel/);
  assert.match(html, /peDfm__control--image/);
  assert.match(html, /aria-label="Image unavailable"/);
  assert.match(html, /peDfm__control--nonvisual[^>]*data-pe-dfm-component="Timer"/);
  assert.match(html, /peDfm__control--unknown[^>]*data-pe-dfm-component="Custom"/);
  assert.match(html, /peDfm__control--unknown[^>]*data-pe-dfm-component="Tall"/);
  assert.match(html, /data-pe-dfm-shape="bsTopLine"/);
  assert.match(html, /peDfm__control--container/);
  assert.match(html, /&#x25c9; Selected/);
  assert.match(html, /white-space:pre-wrap/);
  assert.match(html, /data-pe-dfm-component="Empty"[^>]*white-space:pre-wrap/);
  assert.match(html, /text-align:center/);
  assert.match(html, /background:var\(--bg\)/);
  assert.doesNotMatch(html, />Empty<|>Panel<|>Image<|>Timer</);
});

void test("inherits saved fonts without permitting CSS injection and retains disabled states", () => {
  const root = expectDefined(addTextDfmPreview(`object Form: TForm
    Font.Name = 'A";background:url(https://dfm.invalid/image);/*'
    Font.Size = 9
    Font.Style = [fsBold, fsItalic]
    Color = clBtnFace
    object Button: TNewButton
      Caption = '<b>&'
      Enabled = False
      Font.Style = []
      Alignment = taRightJustify
    end
    object Edit: TEdit
      Text = 'Value'
      Alignment = taLeftJustify
    end
    object Group: TGroupBox
      Caption = 'Group caption'
      Color = clWhite
    end
    object Black: TLabel
      Color = clBlack
      Font.Height = 14
    end
  end`)?.preview?.dfm);
  const html = renderDfmPreview(root).split("<table")[0]!;

  assert.match(html, /font-family:&quot;A\\22 ;background:url\(https:\/\/dfm.invalid/);
  assert.match(html, /font-size:12px/);
  assert.match(html, /font-size:14px/);
  assert.match(html, /font-weight:bold;font-style:italic/);
  assert.match(html, /font-weight:normal;font-style:normal/);
  assert.match(html, /aria-disabled="true">&lt;b&gt;&amp;/);
  assert.match(html, /text-align:right/);
  assert.match(html, /text-align:left/);
  assert.match(html, /peDfm__control--edit/);
  assert.match(html, /peDfm__legend">Group caption/);
  assert.match(html, /background:var\(--pe-dfm-white\)/);
  assert.match(html, /background:var\(--pe-dfm-black\)/);
});

void test("uses finite fallback geometry and clamps progress to valid ranges", () => {
  const root = expectDefined(addTextDfmPreview(`object Form: TForm
    ClientWidth = 0
    ClientHeight = -1
    Font.Size = 1e308
    object Pages: TNewNotebook
      object Inactive: TNewNotebookPage
      end
    end
    object Reverse: TProgressBar
      Min = 50
      Max = 10
      Position = -10
      Width = -5
      Height = -8
    end
    object Over: TProgressBar
      Min = -1e308
      Max = 1e308
      Position = 1e308
    end
  end`)?.preview?.dfm);
  const html = renderDfmPreview(root).split("<table")[0]!;

  assert.match(html, /width:1px;height:1px/);
  assert.match(html, /width:150px;height:150px/);
  assert.match(html, /data-pe-dfm-component="Inactive"[^>]* hidden/);
  assert.match(html, /width:0px;height:0px/);
  assert.match(html, /<progress value="0" max="1"/);
  assert.match(html, /<progress value="1" max="1"/);
  assert.doesNotMatch(html, /Infinity|NaN/);
});

void test("uses saved outer bounds when a form does not stream client dimensions", () => {
  const root = expectDefined(addTextDfmPreview(
    "object Form: TForm\n Width = 320\n Height = 180\n end")?.preview?.dfm);

  assert.match(renderDfmPreview(root), /width:320px;height:180px/);
});

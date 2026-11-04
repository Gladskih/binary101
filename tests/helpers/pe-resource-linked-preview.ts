import type { ResourcePreviewContext } from "../../renderers/pe/resource-preview-context.js";
import { indexResourceLeaves } from "../../analyzers/pe/resources/resource-index.js";
import { collectResourceLinks } from "../../analyzers/pe/resources/resource-links.js";
import type { ResourceDetailGroup } from "../../analyzers/pe/resources/preview/types.js";
import { createPreviewLangEntry, createPreviewDetailGroup } from "./pe-resource-preview-fixture.js";
import { addDialogPreview } from "../../analyzers/pe/resources/preview/dialog.js";
import { createInteractiveDialogResource } from "../fixtures/pe-resource-interactive-payloads.js";

export const linkedDialogPreview = (): ResourcePreviewContext => {
  const detail: ResourceDetailGroup[] = [
    createPreviewDetailGroup("DIALOG",401,{...createPreviewLangEntry(),
      ...addDialogPreview(createInteractiveDialogResource(),"DIALOG")?.preview}),
    createPreviewDetailGroup("MENU",1,{...createPreviewLangEntry(),menuPreview:{templateKind:"standard",helpId:null,
      items:[{text:"File",id:null,type:null,state:null,flags:[],children:[]}]}}),
    createPreviewDetailGroup("BITMAP",1,{...createPreviewLangEntry(),previewDataUrl:"data:image/png;base64,AQ=="}),
    createPreviewDetailGroup("DLGINIT",401,{...createPreviewLangEntry(),dialogInit:{entries:[
      {controlId:102,message:0x403,data:new TextEncoder().encode("<First>\0")}]}}),
    createPreviewDetailGroup("AFX_DIALOG_LAYOUT",401,{...createPreviewLangEntry(),dialogLayout:{version:0,controls:[
      {moveX:0,moveY:0,sizeX:0,sizeY:0},{moveX:0,moveY:0,sizeX:0,sizeY:0},
      {moveX:100,moveY:50,sizeX:50,sizeY:0}]}})
  ];
  return {catalog:indexResourceLeaves(detail),links:collectResourceLinks(detail),source:{group:0,entry:0,language:0}};
};

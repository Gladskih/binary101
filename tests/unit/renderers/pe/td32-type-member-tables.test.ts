import assert from "node:assert/strict";
import {test} from "node:test";
import {buildTd32MemberTables} from "../../../../renderers/pe/td32-type-member-tables.js";
import type {Td32Types} from "../../../../analyzers/pe/debug/td32-type-records.js";

const types = (): Td32Types => ({kind:"types",version:1,records:[
  {index:0,type:4,nameIndex:1,body:{fieldList:0x1001}},
  {index:1,type:0x204,body:{fields:[
    {type:0x406,nameIndex:2,targetType:0x74,attributes:3,offset:{value:"8"}},
    {type:0x408,nameIndex:3,targetType:0x1002,count:1},
    {type:0x403,nameIndex:4,value:{value:"7"}},
    {type:0x405,targetType:0x1004}
  ]}},
  {index:2,type:0x207,body:{methods:[{attributes:0x13,methodType:0x1003,browserOffset:0,vtableOffset:4}]}},
  {index:3,type:9,body:{parameterCount:2,returnType:0x74}},
  {index:4,type:0x204,body:{fields:[{type:0x405,targetType:0x1001}]}},
  {index:5,type:4,body:{fieldList:0x1001}}
]});
void test("TD32 named owners expose readable member names and method signatures",()=>{
  const tables=buildTd32MemberTables(types(),["Widget","Value","Run","Ready"],1,2);
  assert.deepEqual(tables.find(table=>table.key==="typemembers")!.rows,[
    ["Widget","Value","Field","Int32","8","Public","","1","2"],
    ["Widget","Run","Method group","Type name unavailable","","","1","1","2"],
    ["Widget","Ready","Enum value","Type name unavailable","7","","","1","2"]
  ]);
  assert.deepEqual(tables.find(table=>table.key==="typemethods")!.rows,[
    ["Widget","Run","2","Int32","Public","Introducing virtual","4","1","2"]
  ]);
  assert.ok(tables.find(table=>table.key==="typememberissues")!.rows.some(row=>row[1]?.includes("Cyclic")));
});
void test("TD32 members stop missing/wrong continuation targets and retain unavailable names",()=>{
  const data=types();
  data.records[1]!.body!.fields=[{type:0x406,nameIndex:99,targetType:0,attributes:0x1c},
    {type:0x405,targetType:0x2000},{type:0x405,targetType:0x1002}];
  const tables=buildTd32MemberTables(data,["Widget"],2,3);
  assert.equal(tables.find(table=>table.key==="typemembers")!.rows[0]![1],"Unresolved member name");
  assert.equal(tables.find(table=>table.key==="typemembers")!.rows[0]![5],"Unspecified");
  assert.equal(tables.find(table=>table.key==="typememberissues")!.rows.length,2);
  assert.deepEqual(buildTd32MemberTables(data,[],1,2),[]);
});

void test("TD32 method groups report mismatches and never attribute excess or wrong-kind signatures",()=>{
  const data=types();
  data.records[1]!.body!.fields=[{type:0x408,nameIndex:3,targetType:0x1002,count:1},
    {type:0x408,nameIndex:3,targetType:0x2000,count:1}];
  data.records[2]!.body!.methods=[{attributes:3,methodType:0x1000,browserOffset:0},
    {attributes:3,methodType:0x1003,browserOffset:0}];
  const tables=buildTd32MemberTables(data,["Widget","Value","Run"],1,2);
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows.length,1);
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows[0]![2],"Not decoded");
  const issues=tables.find(table=>table.key==="typememberissues")!.rows.map(row=>row[1]);
  assert.ok(issues.some(issue=>issue?.includes("count")));
  assert.ok(issues.some(issue=>issue?.includes("signature")));
  assert.ok(issues.some(issue=>issue?.includes("Method-list target")));
});

void test("TD32 member tables retain unavailable signatures, names and undeclared groups explicitly",()=>{
  const data=types();
  data.records[1]!.body!.fields=[{type:0x408,targetType:0x1002,count:1},
    {type:0x408,nameIndex:99,targetType:0x1002}, {type:0x7777}];
  data.records[2]!.body!.methods=[{attributes:0x1c,methodType:0x1003,browserOffset:0}];
  delete data.records[3]!.body;
  const tables=buildTd32MemberTables(data,["Widget"],1,2);
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows[0]![1],"Unresolved member name");
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows[0]![5],"Unknown method kind");
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows[0]![6],"");
});

void test("TD32 shared member lists expand once while retaining every named owner",()=>{
  const data=types();
  data.records.push(...Array.from({length:100},(_,index)=>({index:10+index,type:4,nameIndex:5+index,
    body:{fieldList:0x1001}})));
  const names=["Widget","Value","Run","Ready",...Array.from({length:100},(_,index)=>`Alias${index}`)];
  const tables=buildTd32MemberTables(data,names,1,2);
  assert.equal(tables.find(table=>table.key==="typemembers")!.rows.length,3);
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows.length,1);
  assert.equal(tables.find(table=>table.key==="typeownership")!.rows.length,101);
  assert.match(tables.find(table=>table.key==="typemembers")!.rows[0]![0]!,/shared by 101 named types/);
});

void test("TD32 shared continuations and method lists expand once across distinct named owners",()=>{
  const data=types();
  data.records[1]!.body!.fields=[{type:0x408,nameIndex:3,targetType:0x1002,count:1},
    {type:0x405,targetType:0x1004}];
  data.records[4]!.body!.fields=[{type:0x406,nameIndex:2}];
  data.records.push({index:6,type:4,nameIndex:5,body:{fieldList:0x1007}},
    {index:7,type:0x204,body:{fields:[{type:0x408,nameIndex:3,targetType:0x1002,count:1},
      {type:0x405,targetType:0x1004}]}});
  const tables=buildTd32MemberTables(data,["Widget","Value","Run","Ready","Other"],1,2);
  assert.equal(tables.find(table=>table.key==="typemembers")!.rows.length,3);
  assert.equal(tables.find(table=>table.key==="typemethods")!.rows.length,1);
  assert.deepEqual(tables.find(table=>table.key==="typeownership")!.rows,
    [["Other.Run","Widget.Run","1","2"],["Other","Widget","1","2"]]);
});

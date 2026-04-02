import{$ as e,u as g,C as d,B as u,D as p}from"./main-C_-UicSA.js";function r(a){e(a).removeClass("bg-success bg-danger text-white border-success border-danger"),e(a).val()==="visible"?e(a).addClass("bg-success text-white border-success"):e(a).val()==="hidden"&&e(a).addClass("bg-danger text-white border-danger")}function h(a,t){e(a).val(t),e(a).data("previous-state",t),r(a)}function b(a){let t=e("input[data-challenge-id]:checked").map(function(){return e(this).data("challenge-id")}),i=t.length===1?"challenge":"challenges";g({title:"Delete Challenges",body:`Are you sure you want to delete ${t.length} ${i}?`,success:function(){const o=[];for(var n of t)o.push(d.fetch(`/api/v1/challenges/${n}`,{method:"DELETE"}));Promise.all(o).then(l=>{window.location.reload()})}})}function v(a){let t=e("input[data-challenge-id]:checked").map(function(){return e(this).data("challenge-id")}),i=e("input[data-challenge-id]:checked").map(function(){return e(this).data("solution-id")});u({title:"Edit Challenges",body:e(`
    <form id="challenges-bulk-edit">
      <div class="form-group">
        <label>Category</label>
        <input type="text" name="category" data-initial="" value="">
      </div>
      <div class="form-group">
        <label>Value</label>
        <input type="number" name="value" data-initial="" value="">
      </div>
      <div class="form-group">
        <label>State</label>
        <select name="state" data-initial="">
          <option value="">--</option>
          <option value="visible">Visible</option>
          <option value="hidden">Hidden</option>
        </select>
      </div>
      <div class="form-group">
        <label>Solution</label>
        <select name="solution" data-initial="">
          <option value="">--</option>
          <option value="visible">Visible</option>
          <option value="hidden">Hidden</option>
          <option value="solved">Solved</option>
        </select>
      </div>
    </form>
    `),button:"Submit",success:function(){const o=[];let n=e("#challenges-bulk-edit").serializeJSON(!0),l={state:n.solution};if(delete n.solution,Object.keys(n).length!==0)for(var s of t)o.push(d.fetch(`/api/v1/challenges/${s}`,{method:"PATCH",body:JSON.stringify(n)}));if(l.state)for(var c of i)c&&o.push(d.fetch(`/api/v1/solutions/${c}`,{method:"PATCH",body:JSON.stringify(l)}));Promise.all(o).then(m=>{window.location.reload()})}})}function f(a){a.stopPropagation();const t=e(a.currentTarget),i=t.data("challenge-id"),o=t.data("previous-state")||t.val(),n=t.val();d.fetch(`/api/v1/challenges/${i}`,{method:"PATCH",body:JSON.stringify({state:n})}).then(l=>l.json()).then(l=>{if(l.success)h(t,l.data.state),p({title:"Success",body:`Challenge ${i} is now ${l.data.state}.`});else{t.val(o),r(t);let s="";for(const c in l.errors)s+=l.errors[c].join(`
`),s+=`
`;u({title:"Error",body:s||"Unable to update challenge state.",button:"OK"})}}).catch(()=>{t.val(o),r(t),u({title:"Error",body:"Unable to update challenge state.",button:"OK"})})}e(()=>{e("#challenges-delete-button").click(b),e("#challenges-edit-button").click(v),e(".challenge-state-select").on("click mousedown mouseup focus",function(a){a.stopPropagation()}),e(".challenge-state-select").each(function(){h(this,e(this).val())}),e(".challenge-state-select").on("change",f)});

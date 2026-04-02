import "./main";
import CTFd from "../compat/CTFd";
import $ from "jquery";
import "../compat/json";
import { ezAlert, ezQuery, ezToast } from "../compat/ezq";

function applyStateSelectStyle(select) {
  $(select)
    .removeClass("bg-success bg-danger text-white border-success border-danger");

  if ($(select).val() === "visible") {
    $(select).addClass("bg-success text-white border-success");
  } else if ($(select).val() === "hidden") {
    $(select).addClass("bg-danger text-white border-danger");
  }
}

function syncStateSelect(select, state) {
  $(select).val(state);
  $(select).data("previous-state", state);
  applyStateSelectStyle(select);
}

function deleteSelectedChallenges(_event) {
  let challengeIDs = $("input[data-challenge-id]:checked").map(function () {
    return $(this).data("challenge-id");
  });
  let target = challengeIDs.length === 1 ? "challenge" : "challenges";

  ezQuery({
    title: "Delete Challenges",
    body: `Are you sure you want to delete ${challengeIDs.length} ${target}?`,
    success: function () {
      const reqs = [];
      for (var chalID of challengeIDs) {
        reqs.push(
          CTFd.fetch(`/api/v1/challenges/${chalID}`, {
            method: "DELETE",
          }),
        );
      }
      Promise.all(reqs).then((_responses) => {
        window.location.reload();
      });
    },
  });
}

function bulkEditChallenges(_event) {
  let challengeIDs = $("input[data-challenge-id]:checked").map(function () {
    return $(this).data("challenge-id");
  });
  let solutionIDs = $("input[data-challenge-id]:checked").map(function () {
    return $(this).data("solution-id");
  });

  ezAlert({
    title: "Edit Challenges",
    body: $(`
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
    `),
    button: "Submit",
    success: function () {
      const reqs = [];
      let data = $("#challenges-bulk-edit").serializeJSON(true);
      let solution_data = { state: data.solution };
      // We don't need the solution field for updating challenges
      delete data["solution"];
      // If we didn't set any challenge fields no need to set challenge data
      if (Object.keys(data).length !== 0) {
        for (var chalID of challengeIDs) {
          reqs.push(
            CTFd.fetch(`/api/v1/challenges/${chalID}`, {
              method: "PATCH",
              body: JSON.stringify(data),
            }),
          );
        }
      }
      // If we set solution field we should update the relevant solutions
      if (solution_data.state) {
        for (var solID of solutionIDs) {
          if (solID) {
            reqs.push(
              CTFd.fetch(`/api/v1/solutions/${solID}`, {
                method: "PATCH",
                body: JSON.stringify(solution_data),
              }),
            );
          }
        }
      }
      Promise.all(reqs).then((_responses) => {
        window.location.reload();
      });
    },
  });
}

function updateChallengeState(event) {
  event.stopPropagation();
  const select = $(event.currentTarget);
  const challengeId = select.data("challenge-id");
  const previousState = select.data("previous-state") || select.val();
  const state = select.val();

  CTFd.fetch(`/api/v1/challenges/${challengeId}`, {
    method: "PATCH",
    body: JSON.stringify({ state: state }),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.success) {
        syncStateSelect(select, response.data.state);
        ezToast({
          title: "Success",
          body: `Challenge ${challengeId} is now ${response.data.state}.`,
        });
      } else {
        select.val(previousState);
        applyStateSelectStyle(select);
        let body = "";
        for (const key in response.errors) {
          body += response.errors[key].join("\n");
          body += "\n";
        }
        ezAlert({
          title: "Error",
          body: body || "Unable to update challenge state.",
          button: "OK",
        });
      }
    })
    .catch(() => {
      select.val(previousState);
      applyStateSelectStyle(select);
      ezAlert({
        title: "Error",
        body: "Unable to update challenge state.",
        button: "OK",
      });
    });
}

$(() => {
  $("#challenges-delete-button").click(deleteSelectedChallenges);
  $("#challenges-edit-button").click(bulkEditChallenges);
  $(".challenge-state-select").on("click mousedown mouseup focus", function (event) {
    event.stopPropagation();
  });
  $(".challenge-state-select").each(function () {
    syncStateSelect(this, $(this).val());
  });
  $(".challenge-state-select").on("change", updateChallengeState);
});
